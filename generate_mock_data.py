"""
Mock ERP transaction generator.

Produces ~500 transactions across 8 GL categories with realistic
distributions, then injects ~5% obvious outliers (3-6 sigma above
the category mean) so the anomaly detector has something to find.

Output: data/transactions.csv
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 42
N_NORMAL = 475
N_OUTLIERS = 25
END_DATE = datetime(2026, 4, 28)
WINDOW_DAYS = 180

# (mean, std) calibrated to look like a small/mid-size company
CATEGORIES = {
    "Travel": {
        "mean": 850, "std": 280,
        "vendors": ["United Airlines", "Marriott", "Hertz", "Uber", "Delta", "Hilton", "Lyft"],
    },
    "Office Supplies": {
        "mean": 120, "std": 40,
        "vendors": ["Staples", "Office Depot", "Amazon Business", "Quill"],
    },
    "Software/SaaS": {
        "mean": 450, "std": 200,
        "vendors": ["Microsoft 365", "Slack", "Zoom", "GitHub", "Atlassian", "AWS", "Notion"],
    },
    "Marketing": {
        "mean": 1200, "std": 600,
        "vendors": ["Google Ads", "LinkedIn Ads", "Facebook Ads", "HubSpot", "Mailchimp"],
    },
    "Consulting": {
        "mean": 5000, "std": 2200,
        "vendors": ["Deloitte", "McKinsey", "Accenture", "Boston Consulting", "FreelancerX"],
    },
    "Equipment": {
        "mean": 1500, "std": 700,
        "vendors": ["Dell", "Apple", "Best Buy", "B&H Photo", "CDW"],
    },
    "Meals & Entertainment": {
        "mean": 90, "std": 50,
        "vendors": ["DoorDash", "Local Restaurant", "Cheesecake Factory", "Starbucks", "GrubHub"],
    },
    "Utilities": {
        "mean": 350, "std": 80,
        "vendors": ["Comcast", "PG&E", "AT&T", "Verizon"],
    },
}

REQUESTERS = [
    ("Alice Chen",    "Engineering"),
    ("Bob Martinez",  "Sales"),
    ("Carol Davis",   "Marketing"),
    ("Devon Patel",   "Finance"),
    ("Erin O'Brien",  "Operations"),
    ("Frank Lee",     "Engineering"),
    ("Grace Kim",     "HR"),
    ("Hugo Bauer",    "Sales"),
]

FIELDS = [
    "transaction_id", "date", "category", "vendor", "amount",
    "requester", "department", "gl_account", "cost_center", "description",
]


def positive_normal(mean: float, std: float) -> float:
    """Truncated normal that never goes below 5% of the mean."""
    floor = max(5.0, mean * 0.05)
    return max(floor, random.gauss(mean, std))


def make_row(txn_id: int, date: datetime, category: str, amount: float) -> dict:
    info = CATEGORIES[category]
    requester, dept = random.choice(REQUESTERS)
    vendor = random.choice(info["vendors"])
    cat_idx = list(CATEGORIES.keys()).index(category)
    return {
        "transaction_id": f"TXN{txn_id}",
        "date": date.strftime("%Y-%m-%d"),
        "category": category,
        "vendor": vendor,
        "amount": round(amount, 2),
        "requester": requester,
        "department": dept,
        "gl_account": f"6{cat_idx:03d}0",
        "cost_center": f"CC-{random.randint(100, 199)}",
        "description": f"{category} - {vendor}",
    }


def main(out_path: Path) -> None:
    random.seed(SEED)
    start = END_DATE - timedelta(days=WINDOW_DAYS)
    rows = []
    txn_id = 100000

    # normal transactions
    for _ in range(N_NORMAL):
        cat = random.choice(list(CATEGORIES.keys()))
        info = CATEGORIES[cat]
        amt = positive_normal(info["mean"], info["std"])
        date = start + timedelta(days=random.randint(0, WINDOW_DAYS))
        rows.append(make_row(txn_id, date, cat, amt))
        txn_id += 1

    # outliers: 3-6 sigma above category mean (these should get flagged)
    for _ in range(N_OUTLIERS):
        cat = random.choice(list(CATEGORIES.keys()))
        info = CATEGORIES[cat]
        sigma_mult = 3.0 + random.random() * 3.0
        amt = info["mean"] + sigma_mult * info["std"]
        date = END_DATE - timedelta(days=random.randint(0, 60))
        rows.append(make_row(txn_id, date, cat, amt))
        txn_id += 1

    # shuffle so outliers aren't all at the bottom
    random.shuffle(rows)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} transactions to {out_path}")


if __name__ == "__main__":
    here = Path(__file__).parent
    main(here / "data" / "transactions.csv")
