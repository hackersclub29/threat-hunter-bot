<div align="center">

# 🎯 Autonomous Threat Hunter Bot

**Packet → Intelligence → Action**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?logo=windows&logoColor=white)](#installation)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-orange)](https://scapy.net/)
[![Discord](https://img.shields.io/badge/Discord-Webhook-5865F2?logo=discord&logoColor=white)](#discord-webhook-setup)
[![aiohttp](https://img.shields.io/badge/aiohttp-3.9%2B-blue)](https://docs.aiohttp.org/)
[![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)

*Blue Team automation that captures live network traffic, enriches external IPs against threat-intel APIs, scores them 0–100, generates AI-powered SOC analyst reports, and fires rich alerts to Discord — fully autonomous, zero manual intervention.*

[Features](#features) • [Architecture](#architecture) • [Quick Start](#quick-start) • [API Keys](#getting-your-api-keys) • [Linux Install](#installation--linux) • [Windows Install](#installation--windows) • [Configuration](#configuration-env) • [Scoring](#scoring-model) • [Troubleshooting](#troubleshooting) • [License](#license)

</div>

---

## Features

- 🔬 **Live packet capture** — Scapy sniffs external IPs and DNS queries from your NIC in real time
- 🌐 **Multi-source enrichment** — IPinfo (geo + privacy flags) + AbuseIPDB (abuse confidence + report history) + Cloudflare DNS (1.1.1.1)
- 📊 **Multi-factor scoring** — weighted 0–100 model across 13 signals (Tor, VPN, bulletproof ASN, country risk, abuse confidence, and more)
- 🤖 **AI threat reports** — Ollama-powered T3 SOC analyst reports with risk indicators, actor profile, and defensive actions
- 📣 **Discord alerts** — colour-coded rich embeds via webhook (no bot token, no privileged intents)
- 🗄️ **Persistent intel log** — SQLite database survives restarts; cross-session IP deduplication saves API quota
- 📁 **Action outputs** — auto-generated `blocklist.txt` and ready-to-paste `iptables` / `netsh` firewall rules
- ⚡ **Async pipeline** — fully non-blocking `asyncio` architecture with token-bucket rate limiting and exponential backoff

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ThreatHunterPipeline                           │
│                                                                     │
│  ┌───────────────┐   asyncio.Queue   ┌───────────────────────────┐ │
│  │ PacketListener│ ────────────────► │      process_loop()       │ │
│  │   (Scapy)     │                   │                           │ │
│  │  · External   │                   │  ┌─────────────────────┐  │ │
│  │    IPs        │                   │  │  EnrichmentEngine   │  │ │
│  │  · DNS queries│                   │  │  ├─ IPinfo API      │  │ │
│  └───────────────┘                   │  │  ├─ AbuseIPDB API   │  │ │
│                                      │  │  └─ Cloudflare DNS  │  │ │
│  ┌───────────────┐                   │  └──────────┬──────────┘  │ │
│  │  CacheManager │◄─── JSON TTL ──── │             ▼             │ │
│  │ threat_cache  │                   │  ┌─────────────────────┐  │ │
│  │    .json      │                   │  │   ScoringEngine     │  │ │
│  └───────────────┘                   │  │   Multi-factor 0–100│  │ │
│                                      │  └──────────┬──────────┘  │ │
│  ┌───────────────┐                   │             ▼             │ │
│  │PersistenceLayer│◄─── SQLite ───── │  ┌─────────────────────┐  │ │
│  │  · intel_log  │                   │  │  AIEngine (Ollama)  │  │ │
│  │  · seen_ips   │                   │  │  T3 SOC Report      │  │ │
│  └───────────────┘                   │  └──────────┬──────────┘  │ │
│                                      │             ▼             │ │
│                                      │  ┌─────────────────────┐  │ │
│                                      │  │    Action Layer     │  │ │
│                                      │  │  ├─ blocklist.txt   │  │ │
│                                      │  │  ├─ firewall_sug.txt│  │ │
│                                      │  │  └─ DiscordNotifier │  │ │
│                                      │  │     Webhook embed   │  │ │
│                                      │  └─────────────────────┘  │ │
│                                      └───────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

**Pipeline flow:**
`PacketListener` → raw IPs/domains queued → `EnrichmentEngine` (IPinfo + AbuseIPDB) → `ScoringEngine` (0–100) → `AIEngine` (Ollama threat report) → `DiscordNotifier` (webhook embed) + file outputs

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/youruser/threat-hunter-bot.git
cd threat-hunter-bot

# 2. Create and activate virtual environment
python3.11 -m venv venv
source venv/bin/activate          # Linux
# venv\Scripts\Activate.ps1       # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp .env.example .env
nano .env

# 5. Run (root required for raw packet capture on Linux)
sudo venv/bin/python main.py

# Run without packet capture (no root needed — good for testing)
python main.py --no-capture
```

---

## Getting Your API Keys

All four services have a **free tier** — no credit card required for any of them.

---

### 1. IPinfo

**Provides:** Geolocation, ASN, org, hostname, privacy flags (Tor / VPN / proxy / hosting) per IP  
**Free tier:** 50,000 requests/month

1. Sign up at [https://ipinfo.io/signup](https://ipinfo.io/signup)
2. Verify your email and log in
3. Click your avatar (top-right) → **API Access**
4. Copy your token — looks like `87503bb4xxxxxxxx`
5. Add to `.env`: `IPINFO_TOKEN=your_token_here`

> Without this key the bot still runs, but geolocation and privacy-flag enrichment will be empty, reducing scoring accuracy.

---

### 2. AbuseIPDB

**Provides:** Community-sourced abuse confidence score (0–100%) and historical report count  
**Free tier:** 1,000 requests/day

1. Register at [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Verify your email and log in
3. Top-right menu → **Account** → **API** tab
4. Click **Create Key** → name it (e.g. `ThreatHunterBot`)
5. Copy the key (long hex string)
6. Add to `.env`: `ABUSEIPDB_KEY=your_key_here`

> Without this key the abuse confidence score will be 0 and scoring relies on IPinfo signals only.

---

### 3. Ollama (AI Threat Reports)

**Provides:** AI-generated T3 SOC analyst reports — risk summary, indicators, actor profile, defensive actions  
**Model used:** `gpt-oss:120b` (configurable)

**Option A — Ollama Cloud (recommended, no local setup):**

1. Create an account at [https://ollama.com](https://ollama.com)
2. Go to **Account Settings** → **API Keys** → **New API Key**
3. Copy the key (format: `xxxxxx.Ds6xxx-xxx`)
4. Add to `.env`:
```dotenv
OLLAMA_HOST=https://ollama.com
OLLAMA_API_KEY=your_key_here
OLLAMA_MODEL=gpt-oss:120b
```

**Option B — Self-hosted Ollama (local, no API key needed):**

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3
```
Then set in `.env`:
```dotenv
OLLAMA_HOST=http://localhost:11434
OLLAMA_API_KEY=
OLLAMA_MODEL=llama3
```

> Without a working Ollama connection, AI reports fall back to `"AI analysis unavailable. Manual review required."` — all other pipeline stages continue normally.

---

### 4. Discord Webhook URL

**Provides:** Rich-embed threat alerts posted to a Discord channel  
**Cost:** Free — no bot account or token needed

See [Discord Webhook Setup](#discord-webhook-setup) below.

---

## Installation — Linux

### Step 1 — Update system packages

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2 — Install Python 3.11+ and build tools

```bash
sudo apt install -y python3.11 python3.11-venv python3.11-dev \
    python3-pip build-essential libpcap-dev git
```

Verify:
```bash
python3.11 --version
# Python 3.11.x
```

### Step 3 — Clone the repository

```bash
git clone https://github.com/youruser/threat-hunter-bot.git
cd threat-hunter-bot
```

### Step 4 — Create a virtual environment

```bash
python3.11 -m venv venv
source venv/bin/activate
# Prompt becomes: (venv) user@host:~$
```

To deactivate when done: `deactivate`

### Step 5 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Verify:
```bash
pip list | grep -E "scapy|aiohttp|dnspython|python-dotenv"
```

### Step 6 — Configure environment

```bash
cp .env.example .env
nano .env
```

Paste and fill in your keys:

```dotenv
# .env — DO NOT COMMIT THIS FILE

IPINFO_TOKEN=your_ipinfo_token_here
ABUSEIPDB_KEY=your_abuseipdb_key_here
OLLAMA_HOST=https://ollama.com
OLLAMA_API_KEY=your_ollama_key_here
OLLAMA_MODEL=gpt-oss:120b
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
CAPTURE_INTERFACE=
```

Save: `Ctrl+O` → `Enter` → `Ctrl+X`

### Step 7 — Run the bot

```bash
# Option A — run as root (simplest)
sudo venv/bin/python main.py

# Option B — grant raw socket capability once, then run without sudo
sudo setcap cap_net_raw+eip venv/bin/python3.11
python main.py

# No packet capture (no root needed — good for testing)
python main.py --no-capture
```

> **Why `venv/bin/python` with sudo?** `sudo` resets shell environment variables and loses the venv activation. The full path ensures all installed packages are found.

---

## Installation — Windows

### Step 1 — Install Python 3.11+

1. Download from [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
2. Run the installer → **check "Add Python to PATH"** on the first screen
3. Verify in a new terminal:

```powershell
python --version
# Python 3.11.x
```

### Step 2 — Install Npcap

Scapy requires the Npcap packet capture driver on Windows.

1. Download from [https://npcap.com/#download](https://npcap.com/#download)
2. Run installer as **Administrator**
3. ✅ Check **"Install Npcap in WinPcap API-compatible mode"**
4. Reboot if prompted

### Step 3 — Open PowerShell as Administrator

Right-click Start → **Windows Terminal (Admin)** or **PowerShell (Admin)**

### Step 4 — Clone the repository

```powershell
git clone https://github.com/youruser/threat-hunter-bot.git
cd threat-hunter-bot
```

### Step 5 — Create a virtual environment

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
# Prompt becomes: (venv) PS C:\threat-hunter-bot>
```

If you see an execution policy error, run this once first:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Step 6 — Install dependencies

```powershell
pip install --upgrade pip
pip install -r requirements.txt

# If Scapy fails, use the complete bundle:
pip install scapy[complete]
```

### Step 7 — Configure environment

```powershell
copy .env.example .env
notepad .env
```

Find your network interface name for `CAPTURE_INTERFACE`:
```powershell
python -c "from scapy.all import get_if_list; print(get_if_list())"
# Output: ['\Device\NPF_{YOUR-GUID-HERE}']
```

Add to `.env`:
```dotenv
CAPTURE_INTERFACE=\Device\NPF_{YOUR-GUID-HERE}
```

### Step 8 — Run the bot

In the **Administrator** PowerShell with venv active:
```powershell
# Full packet capture
python main.py

# Without packet capture
python main.py --no-capture
```

---

## Discord Webhook Setup

1. Open Discord → right-click your target channel → **Edit Channel**
2. **Integrations** → **Webhooks** → **New Webhook**
3. Name it (e.g. `Threat Hunter Bot`) and set an avatar if desired
4. Click **Copy Webhook URL**
   Format: `https://discord.com/api/webhooks/123456789/abcDEFxxx...`
5. Click **Save**
6. Add to `.env`: `DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN`

Test it from the terminal:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"content": "✅ Threat Hunter Bot webhook test"}' \
  "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```

### Alert embed contents

| Risk Level | Colour | Includes |
|---|---|---|
| 🔴 CRITICAL | Red | Score, geo, AbuseIPDB data, indicators, AI report, firewall rules |
| 🟠 HIGH | Orange | Score, geo, AbuseIPDB data, indicators, AI report, firewall rules |
| 🟡 MEDIUM | Yellow | Score, geo, AbuseIPDB data, indicators, AI report |
| 🔵 LOW | Blue | Scored only — no alert sent |
| 🟢 CLEAN | Green | Ignored |

---

## Configuration (.env)

| Variable | Required | Default | Description |
|---|---|---|---|
| `IPINFO_TOKEN` | Recommended | `""` | IPinfo API token |
| `ABUSEIPDB_KEY` | Recommended | `""` | AbuseIPDB API key |
| `OLLAMA_HOST` | Yes | `https://ollama.com` | Ollama API base URL |
| `OLLAMA_API_KEY` | Recommended | `""` | Ollama Cloud API key |
| `OLLAMA_MODEL` | Yes | `gpt-oss:120b` | Model name for AI reports |
| `DISCORD_WEBHOOK_URL` | Recommended | `""` | Full Discord webhook URL |
| `CAPTURE_INTERFACE` | No | auto-detect | NIC name (e.g. `eth0`, `wlan0`) |

### Risk thresholds (`config.py`)

```python
SCORE_CRITICAL = 85   # blocklist + CRITICAL Discord alert
SCORE_HIGH     = 70   # blocklist + firewall suggestion + alert
SCORE_MEDIUM   = 40   # AI report + Discord alert
SCORE_LOW      = 20   # scored only, no alert
```

### High-risk countries (`config.py`)

```python
HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "BY"}
```

Add or remove [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) country codes as needed.

---

## Scoring Model

| Signal | Source | Max Points |
|---|---|---|
| AbuseIPDB confidence score | AbuseIPDB | 50 |
| Abuse report volume | AbuseIPDB | 15 |
| High-risk country | IPinfo | 20 |
| Tor exit node | IPinfo privacy | 25 |
| Proxy / anonymiser | IPinfo privacy | 12 |
| VPN service | IPinfo privacy | 10 |
| Datacenter / hosting IP | IPinfo privacy | 6 |
| Relay service | IPinfo privacy | 8 |
| Usage type (Tor / VPN / Datacenter) | AbuseIPDB | up to 25 |
| Suspicious ASN | IPinfo org | 10 |
| Bulletproof ISP keyword | IPinfo / AbuseIPDB | 7 |
| Active malicious category reports | AbuseIPDB verbose | 5 |

Final score is clamped to **0–100**.

---

## Output Files

| File | Description |
|---|---|
| `threat_cache.json` | API response cache (1-hour TTL). Delete to force fresh lookups. |
| `blocklist.txt` | HIGH+ IPs with score, country, and timestamp. |
| `firewall_suggestions.txt` | Ready-to-review `iptables` and `netsh` rules for MEDIUM+ IPs. |
| `threat_intelligence.db` | SQLite: `intel_log` (full enrichment records) + `seen_ips` (dedup ledger). |
| `threat_hunter.log` | Full timestamped pipeline log. |

### Querying the intel database

```bash
sqlite3 threat_intelligence.db

-- Top 10 threats by score
SELECT ip, score, risk_level, country, org
FROM intel_log ORDER BY score DESC LIMIT 10;

-- Threats by country
SELECT country, COUNT(*) AS total, ROUND(AVG(score),1) AS avg_score
FROM intel_log GROUP BY country ORDER BY total DESC;

-- Risk level breakdown
SELECT risk_level, COUNT(*) FROM intel_log GROUP BY risk_level;

-- All CRITICAL IPs
SELECT ip, score, country, last_seen
FROM intel_log WHERE risk_level = 'CRITICAL';

.quit
```

---

## Troubleshooting

<details>
<summary><b>PermissionError / Operation not permitted (Linux)</b></summary>

Packet capture requires root or `CAP_NET_RAW`:

```bash
# Option A — run as root
sudo venv/bin/python main.py

# Option B — grant capability once, then run as normal user
sudo setcap cap_net_raw+eip venv/bin/python3.11
python main.py
```
</details>

<details>
<summary><b>ModuleNotFoundError after using sudo (Linux)</b></summary>

`sudo` resets environment variables and loses the venv. Always use the full path to the venv Python:

```bash
sudo /full/path/to/project/venv/bin/python main.py
```
</details>

<details>
<summary><b>Scapy fails on Windows / RuntimeError</b></summary>

1. Ensure Npcap is installed with **WinPcap compatibility mode** checked
2. Install the complete Scapy bundle: `pip install scapy[complete]`
3. Run PowerShell as **Administrator**
</details>

<details>
<summary><b>Ollama API error: 401 Unauthorized</b></summary>

`OLLAMA_API_KEY` is missing or incorrect in `.env`. Check for trailing spaces or newline characters around the value.
</details>

<details>
<summary><b>Ollama API error: 404 Not Found</b></summary>

The model name is wrong or unavailable on Ollama Cloud. Browse models at [https://ollama.com/library](https://ollama.com/library) and update `OLLAMA_MODEL` in `.env`.
</details>

<details>
<summary><b>AI reports show "AI analysis unavailable"</b></summary>

All Ollama retries were exhausted. Check `threat_hunter.log` for the exact error line (`Ollama failed (attempt N): ...`). Common causes: wrong API key, wrong `OLLAMA_HOST`, or no outbound internet on port 443.
</details>

<details>
<summary><b>Discord alerts not arriving</b></summary>

1. Confirm `DISCORD_WEBHOOK_URL` starts with `https://discord.com/api/webhooks/`
2. Test it directly:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"content": "test"}' \
  "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
```
3. Check `threat_hunter.log` for `Discord webhook HTTP 4xx` or connection errors
4. If the webhook was deleted in Discord, recreate it and update `.env`
</details>

<details>
<summary><b>AbuseIPDB always returns empty results</b></summary>

`ABUSEIPDB_KEY` is not set. The engine silently skips AbuseIPDB when the key is blank. Add your key to `.env` and restart.
</details>

<details>
<summary><b>Reset seen-IP deduplication (re-process all known IPs)</b></summary>

```bash
sqlite3 threat_intelligence.db "DELETE FROM seen_ips;"
```
</details>

<details>
<summary><b>Clear the API response cache</b></summary>

```bash
rm threat_cache.json
```

The bot recreates it automatically on next run.
</details>

---

## API Free Tiers

| Service | Free Limit | Sign-Up |
|---|---|---|
| IPinfo | 50,000 req/month | [ipinfo.io/signup](https://ipinfo.io/signup) |
| AbuseIPDB | 1,000 req/day | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| Ollama Cloud | Varies by model | [ollama.com](https://ollama.com) |
| Cloudflare DNS (1.1.1.1) | Unlimited | Built-in — no key needed |
| Discord Webhooks | Unlimited* | Built-in — no extra account needed |

*Discord applies per-webhook rate limits (50 requests/second).

---

## Roadmap

- [ ] Redis cache for multi-node deployments
- [ ] MISP / OpenCTI feed ingestion for actor profile enrichment
- [ ] Suricata `eve.json` alert pipe as an additional input source
- [ ] SOAR runbooks triggered on CRITICAL detections
- [ ] Sigma rule generation from Ollama output
- [ ] Web dashboard for the SQLite intel log
- [ ] Optional auto-apply firewall rules (opt-in config flag)

---

## Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -m "feat: describe your change"`
4. Push to your fork: `git push origin feature/your-feature-name`
5. Open a Pull Request

For major changes, please open an issue first to discuss the approach. Keep PRs focused on a single feature or fix.

---

## Security Notes

- **Never commit `.env`** — it contains live API keys and your Discord webhook secret. Ensure `.env` is in `.gitignore`.
- If your Discord webhook URL leaks, rotate it immediately: Edit Channel → Integrations → Webhooks → Delete and recreate.
- `firewall_suggestions.txt` contains `iptables` / `netsh` commands. **Review them before executing** — do not pipe directly to `bash`.
- The bot requires `CAP_NET_RAW` / Administrator privileges for raw socket access only. It **never applies firewall rules automatically**.
- The token-bucket rate limiter in `EnrichmentEngine` keeps API usage safely within free-tier quotas.

---

## License

Copyright 2026 Threat Hunter Bot Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

&nbsp;&nbsp;&nbsp;&nbsp;http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See the [LICENSE](LICENSE) file for the full license text.

---

<div align="center">

Built with ❤️ for the Blue Team community

⭐ **Star this repo if it helped you** — it helps others find it!

</div>
