"""
discord_bot.py — Threat Hunter Discord bot.

Commands:
  !ip <addr>         — Deep-scan single IP
  !domain <name>     — Resolve + AI-analyse domain → auto-scan first IP
  !blocklist         — View current blocklist entries
  !stats             — Cache / session / persistent DB statistics
  !history <ip>      — Look up a previously seen IP from the intelligence DB
  !top               — Top 10 highest-scored IPs from the persistent log
  !summary           — AI executive summary of this session's threats
  !flush <target>    — Invalidate cache for IP or domain
  !help              — Command list

Fixes applied vs original:
  1. Input validation on every user-supplied argument:
       • IPs validated with ipaddress.ip_address()
       • Domains validated against a strict RFC-compliant regex
       • All inputs length-capped before any processing
  2. Consistent, user-friendly error messages — no stack traces or raw exception
     strings are forwarded to Discord.
  3. !stats command now also surfaces PersistenceLayer totals.
  4. Two new commands: !history and !top expose the persistent intel log.
"""
import ipaddress
import logging
import re
from pathlib import Path

import discord
from discord.ext import commands

from cache import CacheManager
from enrichment_engine import EnrichmentEngine
from scoring_engine import ScoringEngine
from ai_engine import AIEngine
from persistence import PersistenceLayer
from config import (
    DISCORD_TOKEN, DISCORD_CHANNEL_ID,
    SCORE_HIGH, BLOCKLIST_FILE,
)

logger = logging.getLogger(__name__)

# ── Validation helpers ────────────────────────────────────────────────────────

# RFC-1123 / RFC-5891 domain label regex; rejects obvious junk and oversized input.
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)
_MAX_DOMAIN_LEN = 253
_MAX_IP_LEN     = 45   # covers IPv6


def _valid_ip(value: str) -> bool:
    if not value or len(value) > _MAX_IP_LEN:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_domain(value: str) -> bool:
    if not value or len(value) > _MAX_DOMAIN_LEN:
        return False
    return bool(_DOMAIN_RE.match(value))


# ── Visual identity ───────────────────────────────────────────────────────────

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


# ── Bot ───────────────────────────────────────────────────────────────────────

class ThreatHunterBot(commands.Bot):

    def __init__(
        self,
        enrichment: EnrichmentEngine,
        scoring: ScoringEngine,
        ai: AIEngine,
        cache: CacheManager,
        persistence: PersistenceLayer,
        session_threats: list,
    ):
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(command_prefix="!", intents=intents, help_command=None)

        self.enrichment      = enrichment
        self.scoring         = scoring
        self.ai              = ai
        self.cache           = cache
        self.persistence     = persistence
        self.session_threats = session_threats

        self._register_commands()

    # ── Commands ─────────────────────────────────────────────────────────────

    def _register_commands(self):

        # ── !ip ──────────────────────────────────────────────────────────────
        @self.command(name="ip")
        async def cmd_ip(ctx, ip_addr: str = None):
            if not ip_addr:
                await ctx.send("Usage: `!ip <address>`")
                return
            if not _valid_ip(ip_addr):
                await ctx.send(
                    f"❌ `{ip_addr[:50]}` is not a valid IP address. "
                    "Please supply a valid IPv4 or IPv6 address."
                )
                return

            msg = await ctx.send(f"🔍 Analysing `{ip_addr}` ...")
            try:
                enrichment = await self.enrichment.enrich_ip(ip_addr)
                scored     = self.scoring.score_ip(enrichment)
                report     = await self.ai.generate_threat_report(scored, enrichment)

                # Persist to intelligence log
                self.persistence.upsert_intel(scored, enrichment)

                embed = self._ip_embed(scored, enrichment, report, source="manual")
                await msg.edit(content=None, embed=embed)

                if scored["score"] >= SCORE_HIGH:
                    fw = self._firewall_block(ip_addr, scored)
                    await ctx.send(f"⚠️ **Auto-generated firewall suggestion:**\n{fw}")

            except Exception:
                logger.exception(f"cmd_ip error for {ip_addr}")
                await msg.edit(
                    content=f"❌ Analysis of `{ip_addr}` failed. "
                            "Check bot logs for details."
                )

        # ── !domain ──────────────────────────────────────────────────────────
        @self.command(name="domain")
        async def cmd_domain(ctx, domain: str = None):
            if not domain:
                await ctx.send("Usage: `!domain <name>`")
                return
            if not _valid_domain(domain):
                await ctx.send(
                    f"❌ `{domain[:60]}` does not look like a valid domain name. "
                    "Please use a fully-qualified domain (e.g. `example.com`)."
                )
                return

            msg = await ctx.send(f"🌐 Resolving `{domain}` via Cloudflare DNS ...")
            try:
                resolved = await self.enrichment.resolve_domain(domain)
                ips      = resolved.get("ips", [])

                if not ips:
                    err = resolved.get("error", "unknown error")
                    await msg.edit(
                        content=f"❌ Could not resolve `{domain}`: {err}"
                    )
                    return

                ai_note = await self.ai.quick_domain_analysis(domain, ips)

                embed = discord.Embed(
                    title=f"🌐 Domain: {domain}",
                    description=ai_note,
                    color=0x7B68EE,
                )
                embed.add_field(
                    name="Resolved IPs",
                    value="\n".join(f"`{ip}`" for ip in ips) or "None",
                    inline=False,
                )
                embed.set_footer(text=FOOTER_TEXT)
                await msg.edit(content=None, embed=embed)

                if ips:
                    await ctx.send(f"🔗 Auto-scanning resolved IP `{ips[0]}`...")
                    await ctx.invoke(self.get_command("ip"), ips[0])

            except Exception:
                logger.exception(f"cmd_domain error for {domain}")
                await msg.edit(content=f"❌ Domain analysis failed. Check bot logs.")

        # ── !blocklist ────────────────────────────────────────────────────────
        @self.command(name="blocklist")
        async def cmd_blocklist(ctx):
            bl = Path(BLOCKLIST_FILE)
            if not bl.exists() or bl.stat().st_size == 0:
                await ctx.send("📋 Blocklist is empty.")
                return
            lines   = bl.read_text().strip().split("\n")
            preview = "\n".join(lines[-20:])
            await ctx.send(
                f"📋 **Blocklist** ({len(lines)} total, showing last 20):\n"
                f"```\n{preview[:1900]}\n```"
            )

        # ── !stats ────────────────────────────────────────────────────────────
        @self.command(name="stats")
        async def cmd_stats(ctx):
            s       = await self.cache.stats()
            threats = len(self.session_threats)
            high    = sum(1 for t in self.session_threats if t["score"] >= SCORE_HIGH)
            total_intel = self.persistence.total_records()
            total_seen  = self.persistence.total_seen()
            risk_bd     = self.persistence.risk_breakdown()

            embed = discord.Embed(title="📊 Session Statistics", color=0x00AAFF)
            embed.add_field(name="Cache", value=(
                f"Total entries: `{s['total']}`\n"
                f"IPs cached:    `{s['ips']}`\n"
                f"Domains:       `{s['domains']}`\n"
                f"Expired:       `{s['expired']}`"
            ), inline=True)
            embed.add_field(name="Session", value=(
                f"Total threats: `{threats}`\n"
                f"HIGH+ alerts:  `{high}`"
            ), inline=True)
            embed.add_field(name="Intel DB (all time)", value=(
                f"IPs analysed: `{total_intel}`\n"
                f"IPs seen:     `{total_seen}`\n"
                f"CRITICAL:     `{risk_bd.get('CRITICAL', 0)}`\n"
                f"HIGH:         `{risk_bd.get('HIGH', 0)}`"
            ), inline=False)
            await ctx.send(embed=embed)

        # ── !history ──────────────────────────────────────────────────────────
        @self.command(name="history")
        async def cmd_history(ctx, ip_addr: str = None):
            if not ip_addr:
                await ctx.send("Usage: `!history <ip>`")
                return
            if not _valid_ip(ip_addr):
                await ctx.send(
                    f"❌ `{ip_addr[:50]}` is not a valid IP address."
                )
                return
            record = self.persistence.get_intel(ip_addr)
            if not record:
                await ctx.send(f"ℹ️ No historical intel found for `{ip_addr}`.")
                return
            risk  = record["risk_level"]
            embed = discord.Embed(
                title=f"{RISK_BADGE.get(risk, risk)}  —  {ip_addr}  [historic]",
                description=f"Score: **{record['score']}/100**",
                color=RISK_COLOR.get(risk, 0x888888),
            )
            embed.add_field(name="Country", value=f"`{record['country']}`", inline=True)
            embed.add_field(name="Org",     value=f"`{record['org'][:50]}`", inline=True)
            reasons = "\n".join(f"• {r}" for r in record["reasons"][:6])
            if reasons:
                embed.add_field(name="Indicators", value=reasons, inline=False)
            embed.add_field(name="First seen", value=record["first_seen"], inline=True)
            embed.add_field(name="Last seen",  value=record["last_seen"],  inline=True)
            embed.set_footer(text=FOOTER_TEXT)
            await ctx.send(embed=embed)

        # ── !top ──────────────────────────────────────────────────────────────
        @self.command(name="top")
        async def cmd_top(ctx):
            rows = self.persistence.top_threats(limit=10)
            if not rows:
                await ctx.send("ℹ️ No intel records yet.")
                return
            lines = [
                f"`{r['ip']:<17}` {RISK_BADGE.get(r['risk_level'], r['risk_level']):<18} "
                f"score=**{r['score']}** {r['country']} — {r['last_seen']}"
                for r in rows
            ]
            embed = discord.Embed(
                title="🏆 Top 10 Threats (all-time)",
                description="\n".join(lines),
                color=0xFF4444,
            )
            embed.set_footer(text=FOOTER_TEXT)
            await ctx.send(embed=embed)

        # ── !summary ──────────────────────────────────────────────────────────
        @self.command(name="summary")
        async def cmd_summary(ctx):
            if not self.session_threats:
                await ctx.send("No threats logged this session yet.")
                return
            msg    = await ctx.send("🤖 Generating AI executive summary...")
            report = await self.ai.batch_summary(self.session_threats)
            embed  = discord.Embed(
                title="🧠 Session Threat Summary",
                description=report,
                color=0x9B59B6,
            )
            embed.set_footer(
                text=f"Based on {len(self.session_threats)} detections this session"
            )
            await msg.edit(content=None, embed=embed)

        # ── !flush ────────────────────────────────────────────────────────────
        @self.command(name="flush")
        async def cmd_flush(ctx, target: str = None):
            if not target:
                await ctx.send("Usage: `!flush <ip|domain>`")
                return
            # Accept either IPs or domain names for flushing
            if not _valid_ip(target) and not _valid_domain(target):
                await ctx.send(
                    f"❌ `{target[:60]}` is not a valid IP or domain name."
                )
                return
            del1 = await self.cache.delete(f"ip:{target}")
            del2 = await self.cache.delete(f"domain:{target}")
            if del1 or del2:
                await ctx.send(f"🗑️ Cache cleared for `{target}`")
            else:
                await ctx.send(f"ℹ️ No cached entry found for `{target}`")

        # ── !help ─────────────────────────────────────────────────────────────
        @self.command(name="help")
        async def cmd_help(ctx):
            embed = discord.Embed(
                title="🎯 Threat Hunter Bot",
                description="Autonomous packet → intelligence → action pipeline",
                color=0x00AAFF,
            )
            cmds = [
                ("!ip <address>",    "Full threat scan: IPinfo + AbuseIPDB + Gemini report"),
                ("!domain <name>",   "DNS resolve via Cloudflare → AI analysis → auto-scan"),
                ("!history <ip>",    "Look up a previously analysed IP from the intel DB"),
                ("!top",             "Top 10 highest-scored IPs from the persistent log"),
                ("!blocklist",       "View current auto-generated blocklist"),
                ("!stats",           "Cache, session, and all-time intel DB statistics"),
                ("!summary",         "AI executive summary of session detections"),
                ("!flush <target>",  "Invalidate cached result for an IP or domain"),
            ]
            for name, desc in cmds:
                embed.add_field(name=f"`{name}`", value=desc, inline=False)
            embed.set_footer(text=FOOTER_TEXT)
            await ctx.send(embed=embed)

    # ── Alert helper (called by pipeline) ────────────────────────────────────

    async def send_alert(self, scored: dict, enrichment: dict, report: str) -> None:
        channel = self.get_channel(DISCORD_CHANNEL_ID)
        if not channel:
            return
        embed = self._ip_embed(scored, enrichment, report, source="auto-detected")
        await channel.send(embed=embed)
        if scored["score"] >= SCORE_HIGH:
            fw = self._firewall_block(scored["ip"], scored)
            await channel.send(f"⚠️ **Auto-generated firewall suggestion:**\n{fw}")

    # ── Embed builder ─────────────────────────────────────────────────────────

    def _ip_embed(
        self, scored: dict, enrichment: dict, report: str, source: str = "manual"
    ) -> discord.Embed:
        risk  = scored["risk_level"]
        embed = discord.Embed(
            title=f"{RISK_BADGE.get(risk, risk)}  —  {scored['ip']}",
            description=f"**Score: {scored['score']}/100**   |   *{source}*",
            color=RISK_COLOR.get(risk, 0x888888),
        )
        city     = scored.get("city", "?")
        country  = scored.get("country", "?")
        org      = scored.get("org", "?")[:50]
        hostname = scored.get("hostname", "")
        geo_val  = f"📍 `{city}, {country}`\n🏢 `{org}`"
        if hostname:
            geo_val += f"\n🔗 `{hostname}`"
        embed.add_field(name="Geolocation", value=geo_val, inline=True)
        embed.add_field(
            name="AbuseIPDB",
            value=(
                f"Confidence: `{scored['abuse_score']}%`\n"
                f"Reports:    `{scored['total_reports']}`\n"
                f"Usage:      `{scored.get('usage_type', 'Unknown')[:30]}`"
            ),
            inline=True,
        )
        if scored["reasons"]:
            indicators = "\n".join(f"• {r}" for r in scored["reasons"][:6])
            embed.add_field(name="⚠️ Indicators", value=indicators, inline=False)
        preview = report[:900] + "\n*(truncated)*" if len(report) > 900 else report
        embed.add_field(name="🤖 AI Threat Report", value=preview, inline=False)
        embed.set_footer(text=FOOTER_TEXT)
        return embed

    # ── Firewall suggestion text ──────────────────────────────────────────────

    @staticmethod
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

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def on_ready(self):
        logger.info(f"Discord bot ready: {self.user} (id={self.user.id})")
        channel = self.get_channel(DISCORD_CHANNEL_ID)
        if channel:
            await channel.send(
                "🟢 **Threat Hunter Bot online.** "
                "Packet capture active. Type `!help` for commands."
            )
