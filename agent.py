"""
Orchestrator for the Expense Anomaly Agent.

Pipeline:
  1. Load mock ERP transactions (data/transactions.csv)
  2. Detect anomalies via per-category z-score
  3. Query the requester for each flag (interactive | seeded | auto)
  4. Classify each (flag, explanation) as RED / YELLOW / GREEN
  5. Export an Excel report under output/

Run modes:
  python agent.py                 # interactive prompts at the terminal
  python agent.py --mode seeded   # use data/seeded_explanations.json
  python agent.py --mode auto     # synthesise plausible explanations (demo)

Set ANTHROPIC_API_KEY to use Claude Haiku for classification; otherwise
the rule-based fallback runs.
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

from anomaly_detector import detect
from classifier import classify
from reporter import write_report
import team_query

ROOT = Path(__file__).parent
DATA_PATH = ROOT / "data" / "transactions.csv"
SEED_PATH = ROOT / "data" / "seeded_explanations.json"
OUT_PATH = ROOT / "output" / "flagged_report.xlsx"

THRESHOLD = 2.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Expense Anomaly Agent")
    p.add_argument("--mode", choices=("interactive", "seeded", "auto"),
                   default="interactive",
                   help="how to collect the requester's explanation")
    p.add_argument("--threshold", type=float, default=THRESHOLD,
                   help="z-score threshold for flagging (default 2.0)")
    p.add_argument("--data", type=Path, default=DATA_PATH)
    p.add_argument("--out",  type=Path, default=OUT_PATH)
    return p.parse_args(argv)


def banner(text: str) -> None:
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def run(args: argparse.Namespace) -> int:
    if not args.data.exists():
        print(f"ERROR: missing {args.data}. Run: python generate_mock_data.py")
        return 2

    df = pd.read_csv(args.data)
    banner(f"Loaded {len(df):,} transactions from {args.data.name}")

    flagged, stats = detect(df, threshold=args.threshold)
    banner(
        f"Detected {len(flagged)} flags out of {len(df):,} txns "
        f"(threshold = {args.threshold}σ, rate = {len(flagged)/len(df):.1%})"
    )

    # Step 3: collect explanations
    if args.mode == "interactive":
        explanations = team_query.collect_interactive(flagged)
    elif args.mode == "seeded":
        if not SEED_PATH.exists():
            print(f"ERROR: missing {SEED_PATH}")
            return 2
        explanations = team_query.collect_seeded(flagged, SEED_PATH)
    else:  # auto
        explanations = team_query.collect_auto(flagged)

    # Step 4: classify each flag (parallelised - LLM calls are I/O bound)
    banner("Classifying explanations...")
    classifications: dict[str, dict] = {}
    counts = {"RED": 0, "YELLOW": 0, "GREEN": 0}

    rows = [r for _, r in flagged.iterrows()]

    def _job(row):
        return row, classify(row.to_dict(), explanations.get(row["transaction_id"], ""))

    with ThreadPoolExecutor(max_workers=2) as pool:
        for row, result in pool.map(_job, rows):
            txn = row["transaction_id"]
            classifications[txn] = result
            counts[result["flag"]] = counts.get(result["flag"], 0) + 1
            print(f"  {txn}  {row['category']:<22} ${row['amount']:>10,.2f}  "
                  f"-> {result['flag']:<6} ({result['method']})  {result['rationale']}")

    banner(
        f"Result: RED={counts['RED']}  YELLOW={counts['YELLOW']}  GREEN={counts['GREEN']}"
    )

    # Step 5: report
    write_report(
        flagged=flagged,
        explanations=explanations,
        classifications=classifications,
        stats=stats,
        total_txns=len(df),
        threshold=args.threshold,
        out_path=args.out,
    )
    print(f"\nReport written to: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(run(parse_args()))
