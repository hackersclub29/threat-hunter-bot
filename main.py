"""
main.py — Threat Hunter Bot — Main Orchestrator
================================================
Pipeline flow:
  PacketListener  →  asyncio.Queue
  process_loop()  →  EnrichmentEngine  →  ScoringEngine  →  AIEngine
                  →  blocklist.txt / firewall_suggestions.txt
                  →  PersistenceLayer (SQLite intel log)
                  →  DiscordNotifier  (webhook push — no bot token required)

Run:
  sudo python main.py            (root required for raw packet capture)
  python main.py --no-capture    (webhook alerts for manually injected IPs only)

Fix applied vs original:
  • Deduplication is now persistent across restarts via PersistenceLayer.is_seen()
    / .mark_seen().  The in-session set (processed_ips) is still kept as a fast
    O(1) guard; seen_ips in SQLite acts as the durable cross-session layer.
    Net effect: restarting the bot no longer re-enriches IPs it already has in
    the intel log, saving API quota.
  • Replaced ThreatHunterBot (discord.py + bot token) with DiscordNotifier
    (webhook-only, no bot token, no privileged gateway intents, no commands).
    asyncio.gather() now runs only process_loop() — no bot.start() coroutine.
"""
import asyncio
import argparse
import logging
import sys
from datetime import datetime, timezone

from config import (
    DISCORD_WEBHOOK_URL,
    SCORE_MEDIUM, SCORE_HIGH,
    BLOCKLIST_FILE, FIREWALL_SUGGESTIONS, CAPTURE_INTERFACE, CAPTURE_BPF,
)
from cache import CacheManager
from enrichment_engine import EnrichmentEngine
from scoring_engine import ScoringEngine
from ai_engine import AIEngine
from discord_notifier import DiscordNotifier
from packet_listener import PacketListener
from persistence import PersistenceLayer

# ── Logging setup ─────────────────────────────────────────────────────────────
import sys

# Force UTF-8 on Windows consoles before any logging is configured.
# reconfigure() is the correct Python 3.7+ API; it works even when stdout
# is a conhost/WT terminal that defaults to cp1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("threat_hunter.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("main")


class ThreatHunterPipeline:

    def __init__(self):
        self.cache           = CacheManager()
        self.persistence     = PersistenceLayer()
        self.enrichment      = EnrichmentEngine(self.cache)
        self.scoring         = ScoringEngine()
        self.ai              = AIEngine()
        self.notifier        = DiscordNotifier()
        self.packet_queue    = asyncio.Queue(maxsize=500)
        self.session_threats: list[dict] = []
        self.listener: PacketListener | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def init(self) -> None:
        await self.enrichment.init()
        await self.ai.init()
        await self.notifier.init()
        logger.info(
            f"Pipeline initialised — "
            f"{self.persistence.total_records()} IPs in persistent intel log"
        )
        # Announce online status to Discord
        await self.notifier.send_startup()

    async def shutdown(self) -> None:
        if self.listener:
            self.listener.stop()
        await self.enrichment.close()
        await self.ai.close()
        await self.notifier.close()
        self.persistence.close()
        logger.info("Pipeline shutdown complete")

    # ── Core processing loop ─────────────────────────────────────────────────

    async def process_loop(self) -> None:
        """
        Consumes items from packet_queue:
          {"type": "ip",     "ip": "x.x.x.x"}
          {"type": "domain", "domain": "example.com"}

        Deduplication is two-tier:
          1. processed_ips — in-memory set; fast guard for the current session.
          2. persistence.is_seen() — SQLite; survives restarts.
        """
        logger.info("Processing loop started")
        processed_ips: set[str] = set()

        while True:
            try:
                item = await asyncio.wait_for(self.packet_queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue

            kind = item.get("type")
            try:
                if kind == "ip":
                    ip = item["ip"]
                    # Fast in-session check first
                    if ip in processed_ips:
                        continue
                    # Persistent cross-session dedup check
                    if self.persistence.is_seen(ip):
                        logger.debug(f"Skipping previously seen IP: {ip}")
                        processed_ips.add(ip)   # warm the in-session cache too
                        continue
                    processed_ips.add(ip)
                    await self._process_ip(ip)

                elif kind == "domain":
                    domain = item["domain"]
                    resolved = await self.enrichment.resolve_domain(domain)
                    for ip in resolved.get("ips", []):
                        if ip not in processed_ips and not self.persistence.is_seen(ip):
                            await self.packet_queue.put({"type": "ip", "ip": ip})

            except Exception as e:
                logger.error(f"Pipeline error on {item}: {e}", exc_info=True)

    async def _process_ip(self, ip: str) -> None:
        """Full pipeline for a single IP."""
        logger.info(f">> Enriching {ip}")
        enrichment = await self.enrichment.enrich_ip(ip)
        scored     = self.scoring.score_ip(enrichment)
        logger.info(f"  Scored {ip}: {scored['score']}/100 ({scored['risk_level']})")

        # Mark as seen *before* API calls so a crash doesn't leave it untracked
        self.persistence.mark_seen(ip)

        # Only fully process MEDIUM and above
        if scored["score"] < SCORE_MEDIUM:
            return

        report = await self.ai.generate_threat_report(scored, enrichment)

        # Persist enriched record to intel log
        self.persistence.upsert_intel(scored, enrichment)

        self.session_threats.append(scored)

        if scored["score"] >= SCORE_HIGH:
            self._append_blocklist(ip, scored)

        self._append_firewall_suggestion(ip, scored)

        # Push alert to Discord via webhook (fire-and-forget with internal error handling)
        await self.notifier.send_alert(scored, enrichment, report)

    # ── Action writers ────────────────────────────────────────────────────────

    @staticmethod
    def _append_blocklist(ip: str, scored: dict) -> None:
        ts    = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry = (
            f"{ip:<18}  "
            f"# score={scored['score']} risk={scored['risk_level']} "
            f"country={scored['country']} ts={ts}\n"
        )
        with open(BLOCKLIST_FILE, "a") as f:
            f.write(entry)
        logger.info(f"Blocklist <- {ip}")

    @staticmethod
    def _append_firewall_suggestion(ip: str, scored: dict) -> None:
        ts      = datetime.now(timezone.utc).isoformat(timespec="seconds")
        reasons = "; ".join(scored["reasons"][:3]) or "N/A"
        block = (
            f"# [{ts}] {scored['risk_level']} {scored['score']}/100 "
            f"| {scored['country']} | {reasons}\n"
            f"iptables -A INPUT  -s {ip} -j DROP\n"
            f"iptables -A OUTPUT -d {ip} -j DROP\n"
            f'netsh advfirewall firewall add rule name="Block {ip}" '
            f"dir=in  action=block remoteip={ip}\n"
            f'netsh advfirewall firewall add rule name="Block {ip}" '
            f"dir=out action=block remoteip={ip}\n\n"
        )
        with open(FIREWALL_SUGGESTIONS, "a") as f:
            f.write(block)

    # ── Runner ────────────────────────────────────────────────────────────────

    async def run(self, enable_capture: bool, loop: asyncio.AbstractEventLoop) -> None:
        await self.init()

        if enable_capture:
            self.listener = PacketListener(
                queue=self.packet_queue,
                loop=loop,
                interface=CAPTURE_INTERFACE,
                bpf_filter=CAPTURE_BPF,
            )
            try:
                self.listener.start()
            except Exception as e:
                logger.error(
                    f"Packet capture failed: {e}\n"
                    "→ Try running with sudo, or use --no-capture for webhook-only mode."
                )

        # Single coroutine — no bot.start() needed with webhook approach
        await self.process_loop()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Autonomous Threat Hunter Bot")
    parser.add_argument(
        "--no-capture",
        action="store_true",
        help="Start without packet capture (webhook alerts still work)",
    )
    args = parser.parse_args()

    if not DISCORD_WEBHOOK_URL:
        logger.warning(
            "DISCORD_WEBHOOK_URL not set — alerts will be logged only. "
            "Add it to .env to enable Discord notifications."
        )

    loop     = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    pipeline = ThreatHunterPipeline()

    try:
        loop.run_until_complete(pipeline.run(
            enable_capture=not args.no_capture,
            loop=loop,
        ))
    except KeyboardInterrupt:
        logger.info("Interrupted - shutting down...")
    finally:
        pending = asyncio.all_tasks(loop)
        if pending:
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(pipeline.shutdown())
        loop.close()


if __name__ == "__main__":
    main()