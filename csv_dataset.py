"""Helpers for security log CSV upload and AI context building."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pandas as pd


def read_csv_bytes(raw: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(raw))


def read_csv_path(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)


def _flagged_mask(df: pd.DataFrame) -> pd.Series:
    if "flagged" not in df.columns:
        return pd.Series(False, index=df.index)
    s = df["flagged"]
    if s.dtype == bool:
        return s
    return s.astype(str).str.lower().isin(("true", "1", "yes"))


def row_to_security_log_text(row: pd.Series, max_len: int = 600) -> str:
    parts: list[str] = []
    for col in row.index:
        v = row[col]
        if pd.isna(v) or (isinstance(v, str) and not v.strip()):
            continue
        parts.append(f"{col}={v}")
    text = " | ".join(parts)
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def build_dataset_summary_for_ai(df: pd.DataFrame, sample_limit: int = 40) -> str:
    """Single text block for one holistic AI analysis of an uploaded log CSV."""
    n = len(df)
    lines: list[str] = [
        "[DATASET MODE] Uploaded security log CSV for holistic analysis.",
        f"Total rows: {n}.",
        f"Columns: {', '.join(str(c) for c in df.columns)}.",
        "",
        "--- Aggregated statistics ---",
    ]

    if "event_type" in df.columns:
        lines.append("Event type counts:")
        lines.append(df["event_type"].value_counts().to_string())
        lines.append("")

    if "severity" in df.columns:
        lines.append("Log-record severity counts:")
        lines.append(df["severity"].value_counts().to_string())
        lines.append("")

    if "flagged" in df.columns:
        fm = _flagged_mask(df)
        lines.append(f"Rows marked flagged: {int(fm.sum())} of {n}")
        lines.append("")

    if "source_ip" in df.columns:
        lines.append("Top source IPs (frequency):")
        lines.append(df["source_ip"].value_counts().head(15).to_string())
        lines.append("")

    fm = _flagged_mask(df)
    if fm.any():
        flagged_df = df.loc[fm]
        take_flagged = min(len(flagged_df), sample_limit)
        sample = flagged_df.head(take_flagged)
        if len(sample) < sample_limit:
            extra = df.loc[~fm].head(sample_limit - len(sample))
            sample = pd.concat([sample, extra])
    else:
        sample = df.head(sample_limit)

    lines.append(
        f"--- Sample rows (up to {len(sample)}; field=value format) — prioritize anomalies ---"
    )
    for i, (_, r) in enumerate(sample.iterrows(), 1):
        lines.append(f"Sample {i}: {row_to_security_log_text(r)}")

    return "\n".join(lines)


def validate_log_dataframe(df: pd.DataFrame) -> tuple[bool, str]:
    if df.empty:
        return False, "The CSV has no data rows."
    if len(df.columns) < 1:
        return False, "The CSV has no columns."
    return True, ""


def summarize_df_quick(df: pd.DataFrame) -> dict[str, Any]:
    """Lightweight stats for the UI (no AI)."""
    out: dict[str, Any] = {"rows": len(df), "columns": list(df.columns)}
    if "event_type" in df.columns:
        out["event_type_counts"] = df["event_type"].value_counts().to_dict()
    if "flagged" in df.columns:
        out["flagged_count"] = int(_flagged_mask(df).sum())
    return out
