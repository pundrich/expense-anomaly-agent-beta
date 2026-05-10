"""
Per-category z-score anomaly detection.

Flags transactions whose amount is more than `threshold` standard
deviations above their category mean. Std/mean are computed in a
single pass with the outliers still in the sample, which is realistic
for a fresh ERP feed where you do not yet know what is anomalous.
"""
from __future__ import annotations

import pandas as pd


def detect(df: pd.DataFrame, threshold: float = 2.0) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (flagged_df, category_stats_df).

    The flagged frame is sorted by z-score descending and includes the
    extra columns: cat_mean, cat_std, cat_median, expected_max,
    z_score, deviation_pct.
    """
    if "amount" not in df.columns or "category" not in df.columns:
        raise ValueError("df must have 'amount' and 'category' columns")

    stats = (
        df.groupby("category")["amount"]
        .agg(["mean", "std", "median", "count"])
        .rename(columns={
            "mean": "cat_mean",
            "std": "cat_std",
            "median": "cat_median",
            "count": "cat_n",
        })
    )

    enriched = df.merge(stats, left_on="category", right_index=True)
    enriched["z_score"] = (enriched["amount"] - enriched["cat_mean"]) / enriched["cat_std"]
    enriched["expected_max"] = enriched["cat_mean"] + threshold * enriched["cat_std"]
    enriched["deviation_pct"] = (
        (enriched["amount"] - enriched["cat_mean"]) / enriched["cat_mean"] * 100.0
    )

    flagged = enriched[enriched["z_score"] > threshold].copy()
    flagged = flagged.sort_values("z_score", ascending=False).reset_index(drop=True)

    # tidy the stats frame for export
    stats = stats.reset_index()

    return flagged, stats
