# config.py
"""
Threat Hunter Bot Configuration
Load from environment or .env file. Never hardcode keys.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ─── API Keys ─────────────────────────────────────────────────────────────────
IPINFO_TOKEN   = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "")

# Ollama
OLLAMA_HOST    = os.getenv("OLLAMA_HOST", "https://ollama.com")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "gpt-oss:120b")

# ─── Discord Webhook ──────────────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# ─── DNS ──────────────────────────────────────────────────────────────────────
DNS_SERVERS = ["1.1.1.1", "1.0.0.1"]

# ─── Packet Capture ───────────────────────────────────────────────────────────
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", None)
CAPTURE_BPF = "ip and not src net 10.0.0.0/8 and not src net 192.168.0.0/16 and not src net 172.16.0.0/12"

# ─── Risk Thresholds ──────────────────────────────────────────────────────────
SCORE_CRITICAL = 85
SCORE_HIGH     = 70
SCORE_MEDIUM   = 40
SCORE_LOW      = 20

# ─── Paths ────────────────────────────────────────────────────────────────────
CACHE_FILE           = "threat_cache.json"
BLOCKLIST_FILE       = "blocklist.txt"
FIREWALL_SUGGESTIONS = "firewall_suggestions.txt"

# ─── Cache ────────────────────────────────────────────────────────────────────
CACHE_TTL_SECONDS = 3600

# ─── High-Risk Geography & Infrastructure ─────────────────────────────────────
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "BY"}
SUSPICIOUS_ASNS     = {"AS4134", "AS4837", "AS9009", "AS58461", "AS45090"}