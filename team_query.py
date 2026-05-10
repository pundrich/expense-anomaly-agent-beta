"""
Team-query interface.

For each flagged transaction we render a short context block that
mirrors what an automated email/Slack ping would say, then collect
an explanation. Three modes:

    interactive  - prompt() each requester at the terminal
    seeded       - load explanations from a JSON file
    auto         - synthesise plausible explanations (used by the demo)

`format_query(...)` is also reused by the LLM classifier so the model
sees the same context the human team would.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Mapping


def format_query(row) -> str:
    """Render the question we would send to the requester."""
    return (
        f"Hi {row['requester']},\n"
        f"Your transaction {row['transaction_id']} on {row['date']} was flagged "
        f"for review.\n"
        f"  Vendor:        {row['vendor']}\n"
        f"  Category:      {row['category']}\n"
        f"  Amount:        ${row['amount']:,.2f}\n"
        f"  Cat. average:  ${row['cat_mean']:,.2f}\n"
        f"  Expected max:  ${row['expected_max']:,.2f} (mean + 2σ)\n"
        f"  Deviation:     +{row['deviation_pct']:.0f}%  ({row['z_score']:.2f}σ)\n"
        f"Could you explain why this expense was higher than expected?"
    )


def collect_interactive(flagged) -> dict[str, str]:
    """Walk through each flagged row and prompt for an explanation."""
    out: dict[str, str] = {}
    for _, row in flagged.iterrows():
        print("\n" + "=" * 72)
        print(format_query(row))
        print("-" * 72)
        try:
            answer = input("Reply: ").strip()
        except EOFError:
            answer = ""
        out[row["transaction_id"]] = answer
    return out


def collect_seeded(flagged, seed_path: Path) -> dict[str, str]:
    """Pull explanations from a JSON file: {txn_id: explanation}."""
    seeds = json.loads(Path(seed_path).read_text())
    return {row["transaction_id"]: seeds.get(row["transaction_id"], "")
            for _, row in flagged.iterrows()}


# --- demo helpers --------------------------------------------------------

GREEN_TEMPLATES = [
    "Pre-approved by the CFO for the Q1 sales summit; receipt attached in Concur.",
    "Annual SaaS contract renewal billed upfront for the year; budgeted in OpEx plan.",
    "Emergency replacement of a failed production server, approved by the CTO.",
    "Client dinner with a key prospect during contract negotiations; covered by entertainment policy.",
    "Conference registration for an industry event that was on the FY26 training plan.",
    "Hardware refresh for two new engineering hires - within the per-headcount budget.",
]

YELLOW_TEMPLATES = [
    "Standard purchase from our preferred vendor, larger order to reduce shipping costs.",
    "Ad campaign performance was strong so we extended it into a second flight.",
    "Travel ended up costing more because flights re-routed last minute due to weather.",
    "Bundled three months of utilities into one invoice from the provider.",
    "Office supply restock for the new floor; will be a one-off increase.",
]

RED_TEMPLATES = [
    "I forgot to check the policy limit before booking it.",
    "Not sure, will need to follow up with the team to find out.",
    "Was unaware that pre-approval was required at this amount.",
    "It was a personal preference for a nicer hotel during the trip.",
    "Did not realize this category had a budget cap.",
]


def collect_auto(flagged, seed: int = 7) -> dict[str, str]:
    """Synthesise a realistic mix of green/yellow/red replies for the demo."""
    rng = random.Random(seed)
    out: dict[str, str] = {}
    # roughly 50% green, 30% yellow, 20% red
    for _, row in flagged.iterrows():
        bucket = rng.random()
        if bucket < 0.5:
            out[row["transaction_id"]] = rng.choice(GREEN_TEMPLATES)
        elif bucket < 0.8:
            out[row["transaction_id"]] = rng.choice(YELLOW_TEMPLATES)
        else:
            out[row["transaction_id"]] = rng.choice(RED_TEMPLATES)
    return out
