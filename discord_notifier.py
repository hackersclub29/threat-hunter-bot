"""
discord_notifier.py — Discord Webhook Alert Sender
====================================================
Sends rich-embed alerts to a Discord channel via Webhook URL.
No bot token. No discord.py. No privileged intents.
Uses the same aiohttp session that the rest of the pipeline already has.

Public API:
  notifier = DiscordNotifier(webhook_url)
  await notifier.init()
  await notifier.send_alert(scored, enrichment, report)
  await notifier.send_startup()
  await notifier.close()
"""
import logging
import aiohttp
from datetime import datetime, timezone

from config import DISCORD_WEBHOOK_URL

logger = logging.getLogger(__name__)

_TIMEOUT = aiohttp.ClientTimeout(total=15)

# ── Visual identity ────────────────────────────────────────────────────────────

RISK_COLOR = {
    "CRITICAL": 0xCC0000,
    "HIGH":     0xFF6600,
    "MEDIUM":   0xFFAA00,
    "LOW":      0x2299FF,
    "CLEAN":    0x00CC66,
}

RISK_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "CLEAN":    "🟢 CLEAN",
}

FOOTER_TEXT = "Threat Hunter Bot | IPinfo + AbuseIPDB + Gemini | Cloudflare DNS"


class DiscordNotifier:
    """
    Webhook-only Discord notifier.
    Builds Discord embed payloads and POSTs them directly to the webhook URL.
    Falls back gracefully (logs warning) if the webhook URL is not configured.
    """

    def __init__(self, webhook_url: str = DISCORD_WEBHOOK_URL):
        self._url     = webhook_url
        self._session: aiohttp.ClientSession | None = None

    async def init(self) -> None:
        self._session = aiohttp.ClientSession(timeout=_TIMEOUT)
        logger.info("DiscordNotifier ready (webhook mode)")

    async def close(self) -> None:
        if self._session:
            await self._session.close()

    # ── Public send methods ────────────────────────────────────────────────────

    async def send_startup(self) -> None:
        """Post a startup notification to the webhook channel."""
        payload = {
            "embeds": [{
                "title": "🟢 Threat Hunter Bot — Online",
                "description": (
                    "Packet capture active.\n"
                    "Pipeline: **PacketListener → Enrichment → Scoring → AI → Webhook**"
                ),
                "color": 0x00CC66,
                "footer": {"text": FOOTER_TEXT},
                "timestamp": _utcnow(),
            }]
        }
        await self._post(payload)

    async def send_alert(
        self,
        scored: dict,
        enrichment: dict,
        report: str,
        source: str = "auto-detected",
    ) -> None:
        """Send a full threat alert embed for a scored IP."""
        risk   = scored["risk_level"]
        embeds = [self._build_alert_embed(scored, enrichment, report, source)]

        payload: dict = {"embeds": embeds}

        # For HIGH+ also append firewall suggestion as a code-block message
        if scored["score"] >= 70:
            payload["content"] = (
                f"⚠️ **Auto-generated firewall suggestion for `{scored['ip']}`:**\n"
                + _firewall_block(scored["ip"], scored)
            )

        await self._post(payload)

    # ── Embed builder ──────────────────────────────────────────────────────────

    def _build_alert_embed(
        self, scored: dict, enrichment: dict, report: str, source: str
    ) -> dict:
        risk  = scored["risk_level"]
        color = RISK_COLOR.get(risk, 0x888888)
        badge = RISK_BADGE.get(risk, risk)

        # ── Geo / org ──────────────────────────────────────────────────────────
        city     = scored.get("city", "?")
        country  = scored.get("country", "?")
        org      = scored.get("org", "?")[:50]
        hostname = scored.get("hostname", "")

        geo_val = f"📍 `{city}, {country}`\n🏢 `{org}`"
        if hostname:
            geo_val += f"\n🔗 `{hostname}`"

        # ── AbuseIPDB field ────────────────────────────────────────────────────
        abuse_val = (
            f"Confidence: `{scored.get('abuse_score', 0)}%`\n"
            f"Reports:    `{scored.get('total_reports', 0)}`\n"
            f"Usage:      `{scored.get('usage_type', 'Unknown')[:30]}`"
        )

        # ── Indicators ────────────────────────────────────────────────────────
        reasons  = scored.get("reasons", [])
        ind_val  = "\n".join(f"• {r}" for r in reasons[:6]) or "None recorded"

        # ── AI Report (truncated to Discord field limit) ───────────────────────
        preview  = report[:900] + "\n*(truncated)*" if len(report) > 900 else report

        fields = [
            {"name": "Geolocation",       "value": geo_val,  "inline": True},
            {"name": "AbuseIPDB",         "value": abuse_val,"inline": True},
            {"name": "⚠️ Indicators",     "value": ind_val,  "inline": False},
            {"name": "🤖 AI Threat Report","value": preview,  "inline": False},
        ]

        return {
            "title":       f"{badge}  —  {scored['ip']}",
            "description": f"**Score: {scored['score']}/100**   |   *{source}*",
            "color":       color,
            "fields":      fields,
            "footer":      {"text": FOOTER_TEXT},
            "timestamp":   _utcnow(),
        }

    # ── HTTP layer ─────────────────────────────────────────────────────────────

    async def _post(self, payload: dict) -> None:
        """POST payload to the webhook URL. Logs on failure, never raises."""
        if not self._url:
            logger.warning("DISCORD_WEBHOOK_URL not set — skipping notification")
            return
        try:
            async with self._session.post(
                self._url,
                json=payload,
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status in (200, 204):
                    logger.debug("Discord webhook delivered")
                elif resp.status == 429:
                    retry_after = (await resp.json()).get("retry_after", 1)
                    logger.warning(
                        f"Discord webhook rate-limited — retry_after={retry_after}s"
                    )
                else:
                    body = await resp.text()
                    logger.error(
                        f"Discord webhook HTTP {resp.status}: {body[:200]}"
                    )
        except aiohttp.ClientError as e:
            logger.error(f"Discord webhook connection error: {e}")
        except Exception as e:
            logger.error(f"Discord webhook unexpected error: {e}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    """ISO 8601 timestamp required by Discord embeds."""
    return datetime.now(timezone.utc).isoformat()


def _firewall_block(ip: str, scored: dict) -> str:
    comment = f"# Risk:{scored['score']}/100 {scored['risk_level']} — {scored['country']}"
    return (
        "```bash\n"
        f"{comment}\n"
        f"# Linux (iptables)\n"
        f"iptables -A INPUT  -s {ip} -j DROP\n"
        f"iptables -A OUTPUT -d {ip} -j DROP\n\n"
        f"# Windows (netsh)\n"
        f'netsh advfirewall firewall add rule name="Block {ip}" dir=in  action=block remoteip={ip}\n'
        f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}\n'
        "```"
    )
