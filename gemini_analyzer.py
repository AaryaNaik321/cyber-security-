"""
Agentic Gemini threat analyzer.

Pipeline
--------
Step 1 – Triage Agent   : Fast classification pass — identify threat type, severity, and confidence.
Step 2 – Deep-Dive Agent: Specialist pass — produces indicators, remediation steps, and real-world context
                          tailored to the threat type found in Step 1.

Both steps call the Gemini API sequentially; together they mimic an autonomous agent chain
where each step reasons on the output of the previous one.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv
from google import genai

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "history"
HISTORY_PATH = DATA_DIR / "threats_history.json"

load_dotenv(BASE_DIR / "backend" / ".env")
load_dotenv(BASE_DIR / ".env")

GEMINI_API_KEY = (
    os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
).strip()
client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

_GEMINI_MODEL = "gemini-2.5-flash"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _call_gemini(prompt: str) -> str:
    """Single Gemini generate_content call; returns raw text."""
    if client is None:
        raise RuntimeError(
            "Set GEMINI_API_KEY in backend/.env (or project-root .env) — see README."
        )
    response = client.models.generate_content(
        model=_GEMINI_MODEL,
        contents=prompt,
    )
    return response.text.strip()


def _parse_json(text: str) -> Dict[str, Any]:
    """Strip markdown fences and parse JSON; falls back to regex extraction."""
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if not match:
            raise ValueError(f"Could not parse JSON from Gemini response:\n{text[:400]}")
        parsed = json.loads(match.group())
    if isinstance(parsed, list) and parsed:
        parsed = parsed[0]
    return parsed


def _normalize_result(obj: Dict[str, Any]) -> Dict[str, Any]:
    sev = str(obj.get("severity", "Medium"))
    if sev not in ("Critical", "High", "Medium", "Low"):
        sev = "Medium"
    conf = obj.get("confidence", 50)
    try:
        conf = int(float(conf))
    except (TypeError, ValueError):
        conf = 50
    conf = max(0, min(100, conf))

    def _listn(key: str, n: int) -> List[str]:
        v = obj.get(key, [])
        if isinstance(v, str):
            return [v] + ["—"] * (n - 1)
        if not isinstance(v, list):
            return ["—"] * n
        out = [str(x) for x in v[:n]]
        while len(out) < n:
            out.append("—")
        return out[:n]

    return {
        "threat_name": str(obj.get("threat_name", "Unknown threat")),
        "threat_category": str(obj.get("threat_category", "Unknown")),
        "severity": sev,
        "confidence": conf,
        "what_it_does": str(obj.get("what_it_does", "")),
        "real_world_example": str(obj.get("real_world_example", "")),
        "prevention_steps": _listn("prevention_steps", 5),
        "recommended_tools": _listn("recommended_tools", 4),
        "immediate_actions": _listn("immediate_actions", 3),
    }


# ---------------------------------------------------------------------------
# History helpers
# ---------------------------------------------------------------------------

def _load_history() -> List[Dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_history_entry(entry: Dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    history = _load_history()
    entry["saved_at"] = datetime.now(timezone.utc).isoformat()
    history.append(entry)
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Agent steps
# ---------------------------------------------------------------------------

def _agent_triage(input_text: str, threat_category: str) -> Dict[str, Any]:
    """
    Step 1 — Triage Agent.
    Quick-classify the log: is this a real threat? What kind? How severe?
    Returns a lightweight triage dict.
    """
    prompt = f"""You are a Triage Security Agent. Your only job is to classify the threat in the log below.
Return ONLY a JSON object — no markdown, no explanation.

Log:
{input_text}

Suspected category hint (may be "Auto-Detect"): {threat_category}

Return this exact JSON:
{{
  "is_threat": true,
  "threat_name": "name of detected threat or 'No Threat Detected'",
  "threat_category": "Phishing or SQL Injection or DDoS Attack or Malware/Ransomware or Brute Force Login or Unknown",
  "severity": "Critical or High or Medium or Low",
  "confidence": 85,
  "triage_reasoning": "one sentence explaining why you classified it this way"
}}"""
    raw = _call_gemini(prompt)
    parsed = _parse_json(raw)
    conf = parsed.get("confidence", 50)
    try:
        conf = int(float(conf))
    except (TypeError, ValueError):
        conf = 50
    parsed["confidence"] = max(0, min(100, conf))
    no_threat_kw = ["no threat", "clean", "safe", "normal", "legitimate"]
    name_lower = str(parsed.get("threat_name", "")).lower()
    if any(k in name_lower for k in no_threat_kw) or parsed.get("confidence", 100) < 20:
        parsed["is_threat"] = False
    else:
        parsed["is_threat"] = True
    return parsed


def _agent_deep_analysis(
    input_text: str,
    triage: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Step 2 — Deep-Dive Specialist Agent.
    Given the triage output, produce a full forensic breakdown.
    Returns a normalized threat-result dict.
    """
    threat_name = triage.get("threat_name", "Unknown")
    threat_category = triage.get("threat_category", "Unknown")
    severity = triage.get("severity", "Medium")
    triage_reason = triage.get("triage_reasoning", "")

    prompt = f"""You are a Deep-Dive Cybersecurity Specialist Agent.
A Triage Agent already classified this log as:
  - Threat Name     : {threat_name}
  - Threat Category : {threat_category}
  - Severity        : {severity}
  - Triage Reasoning: {triage_reason}

Your job is to produce a detailed forensic analysis of the log below.
Return ONLY a JSON object — no markdown, no explanation.

Log:
{input_text}

Return this exact JSON:
{{
  "threat_name": "{threat_name}",
  "threat_category": "{threat_category}",
  "severity": "{severity}",
  "confidence": {triage.get("confidence", 50)},
  "what_it_does": "2-3 sentences explaining exactly what this threat does and how it operates",
  "real_world_example": "One specific real-world attack that matches this pattern, including the year and victim organization if known",
  "prevention_steps": ["detailed step 1", "detailed step 2", "detailed step 3", "detailed step 4", "detailed step 5"],
  "recommended_tools": ["Tool with brief description 1", "Tool with brief description 2", "Tool with brief description 3", "Tool with brief description 4"],
  "immediate_actions": ["urgent action 1", "urgent action 2", "urgent action 3"]
}}"""
    raw = _call_gemini(prompt)
    parsed = _parse_json(raw)
    return _normalize_result(parsed)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_threat(
    input_text: str,
    threat_category: str,
    *,
    save_history: bool = True,
) -> Dict[str, Any]:
    """
    Run the two-step agentic threat analysis pipeline.

    Step 1 (Triage Agent)  → quick classification.
    Step 2 (Deep-Dive Agent) → full forensic report based on Step 1.

    Returns a normalized result dict with an extra ``agent_steps`` key
    that contains the triage reasoning so callers can surface it to the UI.
    """
    triage = _agent_triage(input_text, threat_category)

    if not triage.get("is_threat", True):
        result: Dict[str, Any] = {
            "threat_name": triage.get("threat_name", "No Threat Detected"),
            "threat_category": triage.get("threat_category", "Unknown"),
            "severity": "Low",
            "confidence": triage.get("confidence", 5),
            "what_it_does": "No malicious activity was detected in the provided log.",
            "real_world_example": "N/A",
            "prevention_steps": ["Continue standard monitoring", "—", "—", "—", "—"],
            "recommended_tools": ["SIEM platform", "—", "—", "—"],
            "immediate_actions": ["No immediate action required", "—", "—"],
            "is_threat": False,
        }
    else:
        result = _agent_deep_analysis(input_text, triage)
        result["is_threat"] = True

    result["agent_steps"] = [
        f"[Triage Agent] {triage.get('triage_reasoning', '')}",
        f"[Deep-Dive Agent] Specialist analysis complete — {result.get('threat_name', 'Unknown')} identified.",
    ]

    if save_history:
        _save_history_entry(
            {
                "threat_category_selected": threat_category,
                "input_preview": input_text[:500],
                "result": {k: v for k, v in result.items() if k != "agent_steps"},
            }
        )
    return result
