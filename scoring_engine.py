"""
scoring_engine.py — Multi-factor IP risk scorer.

Weight table:
  AbuseIPDB confidence score  → up to 50 pts  (primary signal)
  Report volume               → up to 15 pts
  Country risk tier           → 0 / 10 / 20 pts
  Privacy flags (VPN/Proxy/Tor/Hosting)
  ASN reputation
  ISP/org keyword matching
  Usage-type flags (datacenter, bulletproof, etc.)

Final score: 0–100
Risk bands: CLEAN / LOW / MEDIUM / HIGH / CRITICAL
"""
import logging
from config import (
    SCORE_CRITICAL, SCORE_HIGH, SCORE_MEDIUM, SCORE_LOW,
    HIGH_RISK_COUNTRIES, SUSPICIOUS_ASNS,
)

logger = logging.getLogger(__name__)

# AbuseIPDB category codes that indicate active malicious behaviour
MALICIOUS_CATEGORIES = {3, 4, 5, 6, 7, 9, 14, 15, 16, 18, 19, 20, 21, 22}

# ISP/org keywords associated with bulletproof or abuse-heavy providers
BULLETPROOF_KEYWORDS = {
    "choopa", "vultr", "digitalocean", "linode", "ovh", "m247",
    "frantech", "leaseweb", "serverius", "sharktech", "psychz",
    "staminus", "hostwinds", "colocrossing", "combahton",
}

USAGE_TYPE_WEIGHTS = {
    "Data Center/Web Hosting/Transit": 8,
    "Content Delivery Network":         5,
    "Search Engine Spider":             2,
    "ISP":                              0,
    "Tor Exit Node":                   25,
    "VPN":                             12,
}


class ScoringEngine:

    def score_ip(self, enrichment: dict) -> dict:
        """
        Returns scoring result dict:
        {
          "ip": str,
          "score": int,           # 0–100
          "risk_level": str,      # CLEAN/LOW/MEDIUM/HIGH/CRITICAL
          "reasons": [str, ...],  # human-readable indicators
          "country": str,
          "org": str,
          "city": str,
          "hostname": str,
          "abuse_score": int,
          "total_reports": int,
          "usage_type": str,
        }
        """
        ip        = enrichment.get("ip", "unknown")
        ipinfo    = enrichment.get("ipinfo", {})
        abuseipdb = enrichment.get("abuseipdb", {})

        score   = 0
        reasons = []

        # ── 1. AbuseIPDB confidence (0–100 → 0–50 pts) ──────────────────────
        abuse_confidence = int(abuseipdb.get("abuseConfidenceScore", 0))
        if abuse_confidence > 0:
            abuse_pts = round(abuse_confidence * 0.50)
            score    += abuse_pts
            if abuse_confidence >= 75:
                reasons.append(f"AbuseIPDB confidence {abuse_confidence}% (high)")
            elif abuse_confidence >= 25:
                reasons.append(f"AbuseIPDB confidence {abuse_confidence}%")

        # ── 2. Report volume (0–15 pts) ──────────────────────────────────────
        total_reports = int(abuseipdb.get("totalReports", 0))
        if total_reports > 0:
            vol_pts = min(total_reports // 2, 15)
            score  += vol_pts
            if total_reports >= 50:
                reasons.append(f"{total_reports} abuse reports on AbuseIPDB")
            elif total_reports >= 5:
                reasons.append(f"{total_reports} abuse reports")

        # ── 3. Country risk ──────────────────────────────────────────────────
        country = ipinfo.get("country", abuseipdb.get("countryCode", ""))
        if country in HIGH_RISK_COUNTRIES:
            score += 20
            reasons.append(f"High-risk country: {country}")

        # ── 4. Privacy flags from IPinfo ─────────────────────────────────────
        privacy = ipinfo.get("privacy", {})
        if privacy:
            if privacy.get("tor"):
                score += 25
                reasons.append("Tor exit node detected")
            elif privacy.get("proxy"):
                score += 12
                reasons.append("Proxy/anonymiser detected")
            elif privacy.get("vpn"):
                score += 10
                reasons.append("VPN service detected")
            if privacy.get("hosting"):
                score += 6
                reasons.append("Datacenter/hosting IP")
            if privacy.get("relay"):
                score += 8
                reasons.append("Apple Private Relay / relay service")

        # ── 5. Usage type from AbuseIPDB ─────────────────────────────────────
        usage_type = abuseipdb.get("usageType", "")
        wt = USAGE_TYPE_WEIGHTS.get(usage_type, 0)
        if wt:
            score += wt
            if wt >= 10:
                reasons.append(f"Usage type: {usage_type}")

        # ── 6. Suspicious ASN ────────────────────────────────────────────────
        org = ipinfo.get("org", abuseipdb.get("isp", ""))
        for asn in SUSPICIOUS_ASNS:
            if asn in org:
                score += 10
                reasons.append(f"Flagged ASN in org: {asn}")
                break

        # ── 7. Bulletproof ISP keyword match ─────────────────────────────────
        org_lower = org.lower()
        isp_lower = abuseipdb.get("isp", "").lower()
        for kw in BULLETPROOF_KEYWORDS:
            if kw in org_lower or kw in isp_lower:
                score += 7
                reasons.append(f"Bulletproof/abuse-heavy provider: {kw}")
                break

        # ── 8. Active malicious category reports ─────────────────────────────
        # (only available in verbose AbuseIPDB calls)
        for report in abuseipdb.get("reports", [])[:10]:
            cats = set(report.get("categories", []))
            if cats & MALICIOUS_CATEGORIES:
                score += 5
                reasons.append("Active malicious category reports (port scan/brute-force/exploit)")
                break

        # ── Clamp & classify ─────────────────────────────────────────────────
        score = max(0, min(score, 100))

        if   score >= SCORE_CRITICAL: risk = "CRITICAL"
        elif score >= SCORE_HIGH:     risk = "HIGH"
        elif score >= SCORE_MEDIUM:   risk = "MEDIUM"
        elif score >= SCORE_LOW:      risk = "LOW"
        else:                         risk = "CLEAN"

        logger.info(f"Scored {ip}: {score}/100 -> {risk}  reasons={len(reasons)}")

        return {
            "ip":            ip,
            "score":         score,
            "risk_level":    risk,
            "reasons":       reasons,
            "country":       country or "Unknown",
            "org":           org or "Unknown",
            "city":          ipinfo.get("city", "Unknown"),
            "hostname":      ipinfo.get("hostname", ""),
            "abuse_score":   abuse_confidence,
            "total_reports": total_reports,
            "usage_type":    usage_type or "Unknown",
        }
