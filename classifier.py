"""
Red / yellow / green flag classifier.

Primary path: call gpt-oss-120b via Groq's OpenAI-compatible endpoint
with the flag context plus the requester's explanation, and parse a
strict JSON response.

Fallback path (no GROQ_API_KEY available): a small keyword
heuristic so the demo is fully runnable offline. The fallback is
deliberately conservative - vague or short replies default to RED.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

PROMPT_TEMPLATE = """You are an internal-controls reviewer for a finance team. \
A transaction was flagged because its amount was unusually high relative to \
its expense category. Read the requester's explanation and decide whether the \
expense should be marked GREEN, YELLOW, or RED.

  GREEN  = Legitimate, well-justified business reason. Pre-approved, contractual, \
emergency, or otherwise consistent with policy.
  YELLOW = Plausible but lacks supporting detail, missing pre-approval, or only \
mildly concerning. Worth a follow-up but not urgent.
  RED    = Insufficient, evasive, or policy-violating. Possible misuse, \
unauthorised spend, or a personal expense.

Transaction:
  Transaction ID:  {transaction_id}
  Vendor:          {vendor}
  Category:        {category}
  Amount:          ${amount:,.2f}
  Category mean:   ${cat_mean:,.2f}
  Expected max:    ${expected_max:,.2f}  (mean + 2σ)
  Deviation:       +{deviation_pct:.0f}%  ({z_score:.2f}σ above mean)
  Requester:       {requester} ({department})
  Date:            {date}

Requester's explanation:
\"\"\"{explanation}\"\"\"

Reply with ONLY a JSON object on a single line, no prose, no code fences:
{{"flag": "GREEN" | "YELLOW" | "RED", "rationale": "<one short sentence>"}}
"""

LLM_MODEL = "openai/gpt-oss-120b"
LLM_BASE_URL = "https://api.groq.com/openai/v1"


def classify(row: dict, explanation: str) -> dict[str, str]:
    """Return {'flag': ..., 'rationale': ..., 'method': 'llm'|'rules'}."""
    if os.getenv("GROQ_API_KEY"):
        try:
            return _classify_llm(row, explanation)
        except Exception as e:  # network/parse problem -> fall back gracefully
            res = _classify_rules(explanation)
            res["rationale"] = f"[LLM unavailable: {e}] " + res["rationale"]
            return res
    return _classify_rules(explanation)


# --- LLM path ------------------------------------------------------------

def _classify_llm(row: dict, explanation: str) -> dict[str, str]:
    from openai import OpenAI  # imported lazily so offline runs don't need the SDK

    client = OpenAI(
        api_key=os.environ["GROQ_API_KEY"],
        base_url=LLM_BASE_URL,
    )
    prompt = PROMPT_TEMPLATE.format(explanation=explanation or "(no reply)", **row)
    resp = client.chat.completions.create(
        model=LLM_MODEL,
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
        reasoning_effort="low",  # gpt-oss is a reasoning model; keep it short
    )
    text = resp.choices[0].message.content.strip()
    parsed = _safe_parse_json(text)
    flag = str(parsed.get("flag", "")).upper().strip()
    if flag not in {"GREEN", "YELLOW", "RED"}:
        # the model went off-script - degrade to rules
        rules = _classify_rules(explanation)
        rules["rationale"] = "[LLM output unparseable] " + rules["rationale"]
        return rules
    return {
        "flag": flag,
        "rationale": str(parsed.get("rationale", "")).strip()[:300],
        "method": "llm",
    }


def _safe_parse_json(text: str) -> dict[str, Any]:
    """Tolerant JSON parser for reasoning-model output.

    Handles markdown code fences, leading reasoning prose, and the case
    where the model emits multiple {...} blocks (analysis + answer).
    Tries the final balanced block first, since reasoning models
    typically place their final answer last.
    """
    # strip ```json ... ``` fences if present
    text = re.sub(r"```(?:json)?\s*|\s*```", "", text)

    # quick win - whole text is already JSON
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    # walk the string and collect every top-level balanced {...}
    candidates: list[str] = []
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                candidates.append(text[start:i + 1])
                start = -1

    # answer usually comes last, so try in reverse
    for candidate in reversed(candidates):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return {}


# --- rules path ----------------------------------------------------------

GREEN_KEYWORDS = (
    "pre-approved", "preapproved", "approved by", "cfo", "ceo", "cto",
    "annual contract", "annual renewal", "emergency", "production",
    "client dinner", "client meeting", "conference", "training plan",
    "headcount", "budgeted", "policy", "receipt attached",
)
YELLOW_KEYWORDS = (
    "preferred vendor", "shipping", "weather", "rerouted", "re-routed",
    "bundled", "extended", "performance was strong", "one-off",
    "restock", "new floor",
)
RED_KEYWORDS = (
    "forgot", "did not realize", "didn't realize", "not sure",
    "personal", "unaware", "no reason", "mistake", "do not recall",
    "don't recall", "didn't know",
)


def _classify_rules(explanation: str) -> dict[str, str]:
    text = (explanation or "").lower().strip()
    if len(text) < 10:
        return {"flag": "RED", "rationale": "No or insufficient explanation provided.", "method": "rules"}
    if any(k in text for k in RED_KEYWORDS):
        return {"flag": "RED", "rationale": "Explanation cites lack of approval, awareness, or a personal reason.", "method": "rules"}
    if any(k in text for k in GREEN_KEYWORDS):
        return {"flag": "GREEN", "rationale": "Explanation references pre-approval or a documented business reason.", "method": "rules"}
    if any(k in text for k in YELLOW_KEYWORDS):
        return {"flag": "YELLOW", "rationale": "Plausible but unverified business reason.", "method": "rules"}
    return {"flag": "YELLOW", "rationale": "Explanation provided but no policy markers found.", "method": "rules"}
