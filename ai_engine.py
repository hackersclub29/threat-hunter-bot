# ai_engine.py — Ollama Cloud API version (final)

import asyncio
import json
import logging
import os
import random
import requests

from config import OLLAMA_API_KEY, OLLAMA_MODEL

logger = logging.getLogger(__name__)

_MAX_RETRIES = 2
_BACKOFF_BASE = 2.0
_BACKOFF_JITTER = 1.0


# ─────────────────────────────────────────────────────────────────────────────
# PROMPTS (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

_THREAT_REPORT_PROMPT = """\
SYSTEM: You are a T3 SOC analyst. Your ONLY job is to fill in the template below. \
Do NOT add any text outside the template.

--- INPUT DATA ---
{data}
-----------------

THREAT SUMMARY:
[2-3 sentences]

RISK INDICATORS:
[bullet list]

ACTOR PROFILE:
[1 line]

DEFENSIVE ACTIONS:
[3 actions]

CONFIDENCE: [High / Medium / Low]
"""

_DOMAIN_PROMPT = """\
SYSTEM: Output exactly 2 sentences.

Domain: {domain}
IPs: {ips}
"""

_BATCH_SUMMARY_PROMPT = """\
SYSTEM: Output exactly 5 bullet points.

Detections:
{threats}
"""


# ─────────────────────────────────────────────────────────────────────────────
# FALLBACKS
# ─────────────────────────────────────────────────────────────────────────────

_FALLBACK_REPORT = "AI analysis unavailable. Manual review required."
_FALLBACK_DOMAIN = "Domain analysis unavailable."
_FALLBACK_SUMMARY = "Summary unavailable."


# ─────────────────────────────────────────────────────────────────────────────
# ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class AIEngine:

    def __init__(self):
        self._model = OLLAMA_MODEL

    async def init(self) -> None:
        logger.info(f"AIEngine using Ollama Cloud API model={self._model}")

    async def close(self) -> None:
        pass

    # ─────────────────────────────────────────────────────────────────────────

    async def generate_threat_report(self, scored: dict, enrichment: dict) -> str:
        payload = {
            "scoring": scored,
            "enrichment": enrichment
        }

        prompt = _THREAT_REPORT_PROMPT.format(
            data=json.dumps(payload, indent=2)
        )

        return await self._call_ollama(prompt, 600, _FALLBACK_REPORT)

    async def quick_domain_analysis(self, domain: str, resolved_ips: list[str]) -> str:
        prompt = _DOMAIN_PROMPT.format(
            domain=domain,
            ips=", ".join(resolved_ips) or "none"
        )
        return await self._call_ollama(prompt, 120, _FALLBACK_DOMAIN)

    async def batch_summary(self, threats: list[dict]) -> str:
        items = [
            f"{t['ip']} {t['score']} {t['risk_level']}"
            for t in threats[:20]
        ]

        prompt = _BATCH_SUMMARY_PROMPT.format(
            threats="\n".join(items)
        )

        return await self._call_ollama(prompt, 300, _FALLBACK_SUMMARY)

    # ─────────────────────────────────────────────────────────────────────────

    async def _call_ollama(self, prompt: str, max_tokens: int, fallback: str) -> str:

        messages = [
            {"role": "user", "content": prompt}
        ]

        for attempt in range(_MAX_RETRIES + 1):
            try:
                text = await asyncio.to_thread(
                    self._generate_once,
                    messages,
                    max_tokens
                )

                if text:
                    return text

                logger.warning("Empty response from Ollama")

            except Exception as e:
                logger.warning(
                    f"Ollama failed (attempt {attempt+1}): {e}"
                )

            if attempt < _MAX_RETRIES:
                delay = (_BACKOFF_BASE ** attempt) + random.uniform(0, _BACKOFF_JITTER)
                await asyncio.sleep(delay)

        return fallback

    # ─────────────────────────────────────────────────────────────────────────

    def _generate_once(self, messages, max_tokens):

        api_key = os.environ.get("OLLAMA_API_KEY", OLLAMA_API_KEY)

        headers = {
            "Content-Type": "application/json"
        }

        if api_key:
            headers["Authorization"] = "Bearer " + api_key

        payload = {
            "model": self._model,
            "messages": messages,
            "stream": True,
            "options": {
                "num_predict": max_tokens
            }
        }

        response = requests.post(
            "https://ollama.com/api/chat",
            json=payload,
            headers=headers,
            stream=True,
            timeout=60
        )

        if response.status_code != 200:
            raise Exception(f"Ollama API error: {response.status_code} {response.text}")

        chunks = []

        for line in response.iter_lines():
            if not line:
                continue

            try:
                data = json.loads(line.decode("utf-8"))
                content = data.get("message", {}).get("content", "")
                if content:
                    chunks.append(content)
            except Exception:
                continue

        return "".join(chunks).strip()