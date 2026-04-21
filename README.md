# 🎯 Autonomous Threat Hunter Bot
**Packet → Intelligence → Action**  
`T5 Expert | Blue Team Automation | Python + Wireshark + Gemini + Discord`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ThreatHunterPipeline                             │
│                                                                         │
│  ┌──────────────┐   asyncio.Queue   ┌──────────────────────────────┐   │
│  │PacketListener│ ────────────────► │      process_loop()          │   │
│  │  (Scapy)     │                   │                              │   │
│  │  - External  │                   │  ┌────────────────────────┐  │   │
│  │    IPs        │                   │  │  EnrichmentEngine      │  │   │
│  │  - DNS query │                   │  │  ├─ IPinfo API          │  │   │
│  └──────────────┘                   │  │  ├─ AbuseIPDB API       │  │   │
│                                     │  │  └─ Cloudflare DNS      │  │   │
│  ┌──────────────┐                   │  └────────────┬───────────┘  │   │
│  │DiscordBot    │◄──── alerts ───── │               ▼              │   │
│  │  !ip         │                   │  ┌────────────────────────┐  │   │
│  │  !domain     │                   │  │  ScoringEngine         │  │   │
│  │  !blocklist  │                   │  │  Multi-factor 0–100    │  │   │
│  │  !stats      │                   │  └────────────┬───────────┘  │   │
│  │  !summary    │                   │               ▼              │   │
│  │  !flush      │                   │  ┌────────────────────────┐  │   │
│  └──────────────┘                   │  │  AIEngine (Gemini)     │  │   │
│                                     │  │  Threat report + triage│  │   │
│  ┌──────────────┐                   │  └────────────┬───────────┘  │   │
│  │ CacheManager │◄── JSON TTL ───── │               ▼              │   │
│  │ threat_cache │                   │  ┌────────────────────────┐  │   │
│  │ .json        │                   │  │  Action Layer          │  │   │
│  └──────────────┘                   │  │  ├─ blocklist.txt      │  │   │
│                                     │  │  ├─ firewall_sug.txt   │  │   │
│                                     │  │  └─ Discord alert      │  │   │
│                                     │  └────────────────────────┘  │   │
│                                     └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Clone / place files in a directory
cd threat_hunter/

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
nano .env          # fill in all keys

# 4. Run (root required for raw packet capture)
sudo python main.py

# Run in bot-only mode (no capture, manual !ip commands)
python main.py --no-capture
```

---

## Discord Bot Setup

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. New Application → Bot → Reset Token → copy to `.env`
3. Enable **Message Content Intent** under Bot → Privileged Gateway Intents
4. OAuth2 → URL Generator → `bot` scope → permissions:
   - Send Messages, Read Message History, Embed Links, Attach Files
5. Invite bot to your server via generated URL
6. Right-click your alert channel → **Copy Channel ID** → paste to `DISCORD_CHANNEL_ID`

---

## Discord Commands

| Command | Description |
|---|---|
| `!ip 1.2.3.4` | Full threat scan: IPinfo + AbuseIPDB + Gemini report |
| `!domain evil.example.com` | DNS resolve via Cloudflare → AI analysis → auto-scan |
| `!blocklist` | View auto-generated blocklist (last 20 entries) |
| `!stats` | Cache hits, session detection count |
| `!summary` | AI executive summary of all session detections |
| `!flush 1.2.3.4` | Invalidate cached result and re-query on next hit |
| `!help` | Full command reference |

---

## Scoring Model

| Factor | Max Points |
|---|---|
| AbuseIPDB confidence score | 50 |
| Report volume | 15 |
| High-risk country (CN/RU/KP/IR/SY/BY) | 20 |
| Tor exit node | 25 |
| Proxy/anonymiser | 12 |
| VPN service | 10 |
| Datacenter/hosting | 6 |
| Usage type (datacenter/VPN/Tor) | up to 25 |
| Suspicious ASN | 10 |
| Bulletproof provider keyword | 7 |
| Active malicious category reports | 5 |

| Score | Risk Level |
|---|---|
| 85–100 | 🔴 CRITICAL |
| 70–84 | 🟠 HIGH |
| 40–69 | 🟡 MEDIUM |
| 20–39 | 🔵 LOW |
| 0–19 | 🟢 CLEAN |

---

## Output Files

| File | Contents |
|---|---|
| `threat_cache.json` | API response cache (1h TTL) |
| `blocklist.txt` | HIGH+ IPs with score/country/timestamp |
| `firewall_suggestions.txt` | iptables + netsh rules (suggestions only) |
| `threat_hunter.log` | Full pipeline log |

---

## API Keys — Free Tiers

| Service | Limit | Link |
|---|---|---|
| IPinfo | 50,000 req/month | https://ipinfo.io/signup |
| AbuseIPDB | 1,000 req/day | https://www.abuseipdb.com/account/api |
| Gemini (Flash) | 15 req/min / 1M req/day | https://aistudio.google.com/app/apikey |
| Cloudflare DNS | Unlimited | Built-in (1.1.1.1 / 1.0.0.1) |

---

## Unlocks Next

- Replace JSON cache with Redis for multi-node deployments
- Add MISP / OpenCTI feed ingestion to enrich actor profiles
- Integrate Suricata alert pipe as additional input source
- Build SOAR runbooks triggered on CRITICAL detections
- Sigma rule generation from Gemini output
