"""Cyber Threat Detector — simplified Streamlit app."""

from __future__ import annotations

import html
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from csv_dataset import (
    build_dataset_summary_for_ai,
    read_csv_bytes,
    read_csv_path,
    row_to_security_log_text,
    summarize_df_quick,
    validate_log_dataframe,
)
from data import get_threat_log_sample
from gemini_analyzer import analyze_threat
from telegram_notifier import send_no_threat_message, send_threat_alert

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "history"
HISTORY_JSON = DATA_DIR / "threats_history.json"

THREAT_OPTIONS = [
    "Auto-Detect",
    "Phishing",
    "SQL Injection",
    "DDoS Attack",
    "Malware/Ransomware",
    "Brute Force",
]

CUSTOM_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
    :root {
        --bg-deep: #050b18;
        --bg-app: #0a1628;
        --bg-elevated: #0d1a32;
        --bg-card: #0f1f38;
        --bg-glass: rgba(15, 31, 56, 0.55);
        --border-subtle: rgba(59, 130, 246, 0.14);
        --border-strong: rgba(6, 182, 212, 0.22);
        --text-primary: #f1f5f9;
        --text-muted: #8ba3c4;
        --accent: #3b82f6;
        --accent-deep: #1d4ed8;
        --cyan: #06b6d4;
        --accent-soft: rgba(59, 130, 246, 0.18);
        --cyan-soft: rgba(6, 182, 212, 0.12);
        --success: #10b981;
        --severity-critical: #ef4444;
        --severity-high: #f59e0b;
        --severity-medium: #eab308;
        --severity-low: #10b981;
        --radius-sm: 8px;
        --radius-md: 14px;
        --radius-pill: 50px;
        --shadow-card: 0 8px 32px rgba(0, 0, 0, 0.45);
        --glow-accent: 0 0 24px rgba(59, 130, 246, 0.35);
        --glow-cyan: 0 0 20px rgba(6, 182, 212, 0.3);
    }

    @keyframes pulse-glow {
        0%, 100% { background-position: 0% 50%; opacity: 0.55; }
        50% { background-position: 100% 50%; opacity: 0.95; }
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes blink {
        0%, 100% { opacity: 1; filter: brightness(1.2); }
        50% { opacity: 0.35; filter: brightness(0.8); }
    }

    * {
        scrollbar-width: thin;
        scrollbar-color: var(--accent) var(--bg-deep);
    }
    *::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    *::-webkit-scrollbar-track {
        background: var(--bg-deep);
        border-radius: 6px;
    }
    *::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, var(--cyan), var(--accent));
        border-radius: 6px;
        border: 1px solid rgba(0, 0, 0, 0.35);
    }

    html, body, [class*="css"] {
        font-family: 'DM Sans', 'Segoe UI', system-ui, sans-serif !important;
        font-size: 15px;
        color: var(--text-primary) !important;
        letter-spacing: 0.01em;
    }

    .stApp {
        background: linear-gradient(160deg, var(--bg-deep) 0%, var(--bg-app) 50%, #050b14 100%) !important;
    }
    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        background: radial-gradient(ellipse 90% 55% at 50% -15%, rgba(59, 130, 246, 0.12), transparent 50%),
                    radial-gradient(ellipse 60% 40% at 100% 100%, rgba(6, 182, 212, 0.08), transparent 45%);
        pointer-events: none;
        z-index: 0;
    }

    .main .block-container {
        position: relative;
        z-index: 1;
        padding-top: 1.25rem !important;
        max-width: 1200px !important;
    }

    [data-testid="stSidebar"] {
        position: relative;
        border-right: 1px solid var(--border-strong) !important;
        background: rgba(5, 11, 24, 0.72) !important;
        backdrop-filter: blur(18px) saturate(1.35);
        -webkit-backdrop-filter: blur(18px) saturate(1.35);
        box-shadow: inset -1px 0 0 var(--border-subtle);
    }
    [data-testid="stSidebar"]::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, var(--accent), var(--cyan));
        z-index: 10;
    }
    [data-testid="stSidebar"] > div:first-child {
        padding-top: 0.5rem;
    }
    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] label {
        color: var(--text-primary) !important;
    }
    [data-testid="stSidebar"] .stCaption {
        color: var(--text-muted) !important;
    }

    [data-testid="stSidebar"] [data-baseweb="select"] > div {
        border-radius: var(--radius-sm) !important;
        border: 1px solid var(--border-strong) !important;
        background: var(--bg-elevated) !important;
        box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.08);
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    [data-testid="stSidebar"] [data-baseweb="select"] > div:hover {
        border-color: var(--accent) !important;
        box-shadow: var(--glow-accent);
    }
    [data-testid="stSidebar"] .stButton > button {
        background: transparent !important;
        color: var(--accent) !important;
        border: 1px solid var(--accent) !important;
        border-radius: var(--radius-pill) !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        border-color: var(--cyan) !important;
        background: var(--accent-soft) !important;
        box-shadow: var(--glow-cyan);
        color: var(--text-primary) !important;
    }

    .app-hero {
        position: relative;
        overflow: hidden;
        border-radius: var(--radius-md);
        margin-bottom: 1.5rem;
        border: 1px solid var(--border-subtle);
        background: var(--bg-glass);
        backdrop-filter: blur(20px) saturate(1.4);
        -webkit-backdrop-filter: blur(20px) saturate(1.4);
        box-shadow: var(--shadow-card), 0 0 0 1px rgba(6, 182, 212, 0.08) inset;
    }
    .hero-pulse-bg {
        position: absolute;
        inset: -40%;
        background: linear-gradient(
            125deg,
            rgba(59, 130, 246, 0.25) 0%,
            rgba(6, 182, 212, 0.15) 35%,
            rgba(29, 78, 216, 0.2) 70%,
            rgba(6, 182, 212, 0.12) 100%
        );
        background-size: 220% 220%;
        animation: pulse-glow 10s ease-in-out infinite;
        pointer-events: none;
        z-index: 0;
    }
    .app-hero-inner {
        position: relative;
        z-index: 1;
        padding: 1.5rem 1.65rem 1.4rem;
    }
    .hero-top-row {
        display: flex;
        align-items: flex-start;
        gap: 1.1rem;
        margin-bottom: 1rem;
    }
    .hero-shield {
        font-size: 3.1rem;
        line-height: 1;
        filter: drop-shadow(0 0 14px rgba(59, 130, 246, 0.65)) drop-shadow(0 0 8px rgba(6, 182, 212, 0.45));
        flex-shrink: 0;
    }
    .hero-titles { flex: 1; min-width: 0; }
    .hero-line1 {
        margin: 0 0 0.2rem 0;
        font-size: 1.75rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        background: linear-gradient(90deg, var(--text-primary), var(--cyan));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .hero-line2 {
        margin: 0;
        font-size: 1.05rem;
        font-weight: 600;
        color: var(--text-muted);
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .hero-subtext {
        margin: 0 0 1.15rem 0;
        color: var(--text-muted);
        font-size: 0.95rem;
        line-height: 1.6;
        max-width: 54rem;
    }
    .hero-pills {
        display: flex;
        flex-wrap: wrap;
        gap: 0.55rem;
    }
    .hero-pill {
        display: inline-block;
        padding: 0.45rem 0.95rem;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: var(--text-primary);
        border-radius: var(--radius-pill);
        border: 1px solid rgba(59, 130, 246, 0.45);
        background: rgba(59, 130, 246, 0.1);
        box-shadow: 0 0 16px rgba(59, 130, 246, 0.25), 0 0 0 1px rgba(6, 182, 212, 0.2) inset;
    }

    .sidebar-brand {
        padding-bottom: 1rem;
        margin-bottom: 1rem;
        border-bottom: 1px solid var(--border-strong);
        text-align: left;
    }
    .sidebar-title-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 0.65rem;
        flex-wrap: wrap;
        margin-bottom: 0.4rem;
    }
    .sidebar-app-title {
        color: var(--text-primary) !important;
        font-weight: 800 !important;
        font-size: 1.2rem !important;
        margin: 0 !important;
        letter-spacing: -0.02em;
        text-shadow: 0 0 28px rgba(59, 130, 246, 0.45);
    }
    .sidebar-version {
        display: inline-block;
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--cyan);
        padding: 0.28rem 0.55rem;
        border-radius: 6px;
        border: 1px solid rgba(6, 182, 212, 0.45);
        background: rgba(6, 182, 212, 0.12);
        box-shadow: 0 0 12px rgba(6, 182, 212, 0.25);
    }
    .sidebar-tagline {
        color: var(--text-muted) !important;
        font-size: 0.8rem !important;
        margin: 0 !important;
        line-height: 1.45 !important;
    }
    .sidebar-section-title {
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        color: var(--cyan) !important;
        margin: 1.15rem 0 0.6rem 0 !important;
    }

    .section-label {
        font-weight: 700;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        color: var(--accent);
        margin-bottom: 0.65rem;
        display: flex;
        align-items: center;
        gap: 0.45rem;
    }
    .section-label span {
        letter-spacing: normal;
        text-transform: none;
        font-size: 1.05em;
        line-height: 1;
        opacity: 0.95;
    }

    .panel-hint {
        color: var(--text-muted);
        margin: 0 0 1rem 0;
        line-height: 1.65;
        font-size: 0.9rem;
    }
    .panel-hint code {
        background: var(--accent-soft);
        color: #7dd3fc;
        padding: 0.12rem 0.45rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82em;
        border: 1px solid rgba(6, 182, 212, 0.25);
    }

    .card-surface {
        background: var(--bg-card);
        border: 1px solid var(--border-strong);
        border-radius: var(--radius-md);
        padding: 1rem 1.15rem;
        margin-bottom: 1rem;
        box-shadow: var(--shadow-card);
        transition: all 0.2s ease;
    }

    .box-grey, .box-light, .box-full {
        position: relative;
        background: linear-gradient(145deg, var(--bg-card) 0%, var(--bg-elevated) 100%);
        border: 1px solid var(--border-strong);
        border-radius: var(--radius-md);
        padding: 1.15rem 1.2rem 1.15rem 1.35rem;
        margin-bottom: 1rem;
        box-shadow: var(--shadow-card);
        overflow: hidden;
        transition: all 0.2s ease;
        animation: fadeInUp 0.55s ease forwards;
        opacity: 0;
    }
    .box-grey {
        border-left: 3px solid var(--accent);
        animation-delay: 0.06s;
    }
    .box-light {
        border-left: 3px solid var(--cyan);
        animation-delay: 0.14s;
    }
    .box-full {
        border-left: 3px solid rgba(59, 130, 246, 0.65);
        animation-delay: 0.22s;
    }
    .box-grey:hover, .box-light:hover, .box-full:hover {
        border-color: rgba(59, 130, 246, 0.45);
        box-shadow: var(--shadow-card), 0 0 28px rgba(59, 130, 246, 0.18);
    }
    .box-body-text {
        margin: 0;
        color: var(--text-primary);
        line-height: 1.68;
    }

    .threat-title {
        color: var(--text-primary) !important;
        font-size: 1.28rem !important;
        font-weight: 700 !important;
        line-height: 1.35 !important;
        margin: 0 !important;
    }
    .confidence-text {
        color: var(--text-muted) !important;
        font-size: 0.95rem !important;
        margin: 0 !important;
    }

    .sev-critical, .sev-high, .sev-medium, .sev-low {
        position: relative;
        display: inline-flex;
        align-items: center;
        padding: 0.55rem 1.15rem 0.55rem 0.95rem;
        border-radius: var(--radius-pill);
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        border: 1px solid transparent;
        vertical-align: middle;
    }
    .sev-critical::before, .sev-high::before, .sev-medium::before, .sev-low::before {
        content: "";
        display: inline-block;
        width: 9px;
        height: 9px;
        border-radius: 50%;
        margin-right: 0.55rem;
        flex-shrink: 0;
    }
    .sev-critical {
        color: #fecaca;
        background: rgba(239, 68, 68, 0.2);
        border-color: rgba(239, 68, 68, 0.45);
        box-shadow: 0 0 20px rgba(239, 68, 68, 0.35);
    }
    .sev-critical::before {
        background: var(--severity-critical);
        box-shadow: 0 0 10px var(--severity-critical);
        animation: blink 1.25s ease-in-out infinite;
    }
    .sev-high {
        color: #fde68a;
        background: rgba(245, 158, 11, 0.18);
        border-color: rgba(245, 158, 11, 0.45);
        box-shadow: 0 0 18px rgba(245, 158, 11, 0.28);
    }
    .sev-high::before {
        background: var(--severity-high);
        box-shadow: 0 0 8px var(--severity-high);
    }
    .sev-medium {
        color: #fef08a;
        background: rgba(234, 179, 8, 0.16);
        border-color: rgba(234, 179, 8, 0.4);
        box-shadow: 0 0 14px rgba(234, 179, 8, 0.22);
    }
    .sev-medium::before {
        background: var(--severity-medium);
        box-shadow: 0 0 6px var(--severity-medium);
    }
    .sev-low {
        color: #a7f3d0;
        background: rgba(16, 185, 129, 0.16);
        border-color: rgba(16, 185, 129, 0.42);
        box-shadow: 0 0 16px rgba(16, 185, 129, 0.28);
    }
    .sev-low::before {
        background: var(--severity-low);
        box-shadow: 0 0 8px var(--severity-low);
    }

    .prevention-list {
        margin: 0;
        padding-left: 1.35rem;
        line-height: 1.85;
    }
    .prevention-list li {
        margin-bottom: 0.55rem;
        color: var(--text-primary);
    }
    .bullet-tight ul {
        margin: 0;
        padding-left: 1.2rem;
        line-height: 1.8;
    }
    .bullet-tight li {
        margin-bottom: 0.45rem;
        color: var(--text-primary);
    }

    textarea, [data-baseweb="textarea"] textarea {
        font-family: 'JetBrains Mono', 'Cascadia Code', monospace !important;
        font-size: 13px !important;
        border-radius: var(--radius-sm) !important;
        border: 1px solid var(--border-strong) !important;
        border-left: 3px solid var(--accent) !important;
        background: var(--bg-elevated) !important;
        box-shadow: inset 0 2px 12px rgba(0, 0, 0, 0.35), 0 0 20px rgba(59, 130, 246, 0.12) !important;
        color: var(--text-primary) !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    textarea:focus, [data-baseweb="textarea"] textarea:focus {
        border-left-color: var(--cyan) !important;
        box-shadow: inset 0 2px 12px rgba(0, 0, 0, 0.4), 0 0 24px rgba(6, 182, 212, 0.22) !important;
    }

    [data-baseweb="base-input"] input {
        border-radius: var(--radius-sm) !important;
    }

    div[data-testid="stVerticalBlock"] > div {
        gap: 0.55rem;
    }

    .stButton > button {
        border-radius: var(--radius-pill) !important;
        font-weight: 700 !important;
        font-size: 0.88rem !important;
        letter-spacing: 0.02em;
        transition: all 0.2s ease !important;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(180deg, var(--accent) 0%, var(--accent-deep) 100%) !important;
        color: #ffffff !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        box-shadow: 0 4px 20px rgba(29, 78, 216, 0.45) !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(180deg, #60a5fa 0%, var(--accent) 100%) !important;
        box-shadow: 0 6px 28px rgba(59, 130, 246, 0.55), 0 0 24px rgba(6, 182, 212, 0.25) !important;
        transform: translateY(-1px);
    }
    .stButton > button[kind="secondary"] {
        background: transparent !important;
        color: var(--accent) !important;
        border: 1px solid var(--accent) !important;
        box-shadow: none !important;
    }
    .stButton > button[kind="secondary"]:hover {
        background: var(--accent-soft) !important;
        color: var(--text-primary) !important;
        border-color: var(--cyan) !important;
        box-shadow: 0 0 18px rgba(59, 130, 246, 0.25) !important;
    }

    [data-testid="stTabs"] {
        margin-top: 0.35rem;
    }
    .block-container [data-testid="stTabs"] > div > [data-baseweb="tab-list"] {
        gap: 0.35rem !important;
        padding: 0.35rem !important;
        background: rgba(15, 31, 56, 0.85) !important;
        border: 1px solid var(--border-strong) !important;
        border-radius: var(--radius-pill) !important;
    }
    .block-container [data-testid="stTabs"] [data-baseweb="tab"] {
        color: var(--text-muted) !important;
        font-weight: 700 !important;
        font-size: 0.88rem !important;
        border-radius: var(--radius-pill) !important;
        padding: 0.55rem 1.15rem !important;
        margin: 0 !important;
        border: none !important;
        background: transparent !important;
    }
    .block-container [data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {
        color: var(--text-primary) !important;
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.45), rgba(6, 182, 212, 0.25)) !important;
        box-shadow: 0 0 20px rgba(59, 130, 246, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.08);
    }
    [role="tabpanel"] [data-testid="stTabs"] > div > [data-baseweb="tab-list"] {
        gap: 0 !important;
        padding: 0 0 0.15rem 0 !important;
        background: transparent !important;
        border: none !important;
        border-radius: 0 !important;
        border-bottom: 2px solid var(--border-strong) !important;
    }
    [role="tabpanel"] [data-testid="stTabs"] [data-baseweb="tab"] {
        border-radius: var(--radius-sm) var(--radius-sm) 0 0 !important;
        padding: 0.55rem 1rem !important;
        background: transparent !important;
    }
    [role="tabpanel"] [data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {
        color: var(--cyan) !important;
        background: transparent !important;
        box-shadow: none !important;
        border-bottom: 2px solid var(--cyan) !important;
        margin-bottom: -2px !important;
    }

    [data-testid="stMetric"] {
        position: relative;
        background: var(--bg-card);
        border: 1px solid var(--border-strong);
        border-radius: var(--radius-md);
        padding: 1rem 1.1rem 0.95rem;
        box-shadow: var(--shadow-card);
        overflow: hidden;
    }
    [data-testid="stMetric"]::before {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, var(--accent), var(--cyan));
    }
    [data-testid="stMetric"] label {
        color: var(--text-muted) !important;
        font-size: 0.72rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-size: 1.65rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.02em;
    }

    [data-testid="stExpander"] details {
        background: var(--bg-card);
        border: 1px solid var(--border-strong);
        border-radius: var(--radius-sm);
        transition: all 0.2s ease;
    }
    [data-testid="stExpander"] details:hover {
        border-color: rgba(59, 130, 246, 0.4);
        box-shadow: 0 0 20px rgba(59, 130, 246, 0.12);
    }

    div[data-testid="stFileUploader"] section {
        position: relative;
        background: var(--bg-elevated) !important;
        border: 2px dashed rgba(59, 130, 246, 0.35) !important;
        border-radius: var(--radius-md) !important;
        padding-top: 2.5rem !important;
        transition: all 0.2s ease !important;
    }
    div[data-testid="stFileUploader"] section::before {
        content: "☁";
        display: block;
        text-align: center;
        font-size: 2.25rem;
        line-height: 1;
        margin-bottom: 0.35rem;
        color: var(--text-muted);
        opacity: 0.55;
        pointer-events: none;
    }
    div[data-testid="stFileUploader"] section:hover {
        border-color: var(--cyan) !important;
        box-shadow: 0 0 28px rgba(6, 182, 212, 0.25), 0 0 40px rgba(59, 130, 246, 0.15) !important;
    }
    div[data-testid="stFileUploader"] section:hover::before {
        color: var(--cyan);
        opacity: 0.85;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border-strong) !important;
        border-radius: var(--radius-sm) !important;
        overflow: hidden;
        background: var(--bg-card) !important;
    }
    [data-testid="stDataFrame"] > div,
    [data-testid="stDataFrame"] [class*="glide"] {
        background: var(--bg-card) !important;
    }
    [data-testid="stDataFrame"] [role="grid"] {
        background: var(--bg-elevated) !important;
    }
    [data-testid="stDataFrame"] [role="columnheader"],
    [data-testid="stDataFrame"] [data-testid="column-header"] {
        color: var(--cyan) !important;
        font-weight: 700 !important;
        background: var(--bg-deep) !important;
    }
    [data-testid="stDataFrame"] [role="gridcell"] {
        color: var(--text-primary) !important;
        border-color: var(--border-subtle) !important;
    }

    hr {
        border: none;
        border-top: 1px solid var(--border-strong);
        margin: 1.35rem 0;
    }

    .app-footer {
        margin-top: 2.5rem;
        margin-bottom: 1rem;
        padding: 1rem 1.25rem;
        text-align: center;
        font-size: 0.78rem;
        color: var(--text-muted);
        letter-spacing: 0.04em;
        border-top: 1px solid rgba(59, 130, 246, 0.35);
        background: linear-gradient(180deg, rgba(15, 31, 56, 0.6), rgba(5, 11, 24, 0.85));
        border-radius: var(--radius-sm);
    }

    .stAlert [data-testid="stMarkdownContainer"] p {
        color: inherit;
    }
</style>
"""


def init_session():
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "history_refresh" not in st.session_state:
        st.session_state.history_refresh = 0
    if "csv_df" not in st.session_state:
        st.session_state.csv_df = None
    if "csv_dataset_ai_result" not in st.session_state:
        st.session_state.csv_dataset_ai_result = None
    if "csv_row_results" not in st.session_state:
        st.session_state.csv_row_results = None
    if "csv_upload_fingerprint" not in st.session_state:
        st.session_state.csv_upload_fingerprint = None


def notify_analysis_telegram(result: dict | None) -> None:
    if not result:
        return
    is_threat = result.get("is_threat", True)
    if is_threat:
        with st.spinner("Sending Telegram alert..."):
            success, msg = send_threat_alert(result)
        if success:
            st.success("📱 Telegram alert sent successfully!")
        else:
            st.error(f"Telegram notification failed: {msg}")
    else:
        st.success("✅ No Threat Detected — Data appears clean and safe.")
        st.info("No suspicious patterns found in the submitted data.")
        ok = send_no_threat_message()
        if ok:
            st.success("📱 Telegram notified: No threat found.")
        else:
            st.error("Telegram notification failed for no-threat update.")


def load_history_raw() -> list:
    if not HISTORY_JSON.exists():
        return []
    try:
        with open(HISTORY_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def clear_history_file():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_JSON, "w", encoding="utf-8") as f:
        json.dump([], f)
    st.session_state.history_refresh += 1


def severity_class(sev: str) -> str:
    return {
        "Critical": "sev-critical",
        "High": "sev-high",
        "Medium": "sev-medium",
        "Low": "sev-low",
    }.get(sev, "sev-medium")


def render_result(res: dict):
    name = html.escape(str(res.get("threat_name", "—")))
    sev = res.get("severity", "Medium")
    conf = int(res.get("confidence", 0))

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f'<p class="threat-title">{name}</p>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<span class="{severity_class(sev)}">{html.escape(str(sev))}</span>',
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<p class="confidence-text">{conf}% confident</p>',
            unsafe_allow_html=True,
        )

    what_txt = html.escape(str(res.get("what_it_does", "")))
    st.markdown(
        '<div class="box-grey"><p class="section-label"><span>⚡</span> What is this threat?</p>'
        f'<p class="box-body-text">{what_txt}</p></div>',
        unsafe_allow_html=True,
    )

    rw_txt = html.escape(str(res.get("real_world_example", "")))
    st.markdown(
        '<div class="box-light"><p class="section-label"><span>🌐</span> Real World Example</p>'
        f'<p class="box-body-text">{rw_txt}</p></div>',
        unsafe_allow_html=True,
    )

    steps = res.get("prevention_steps", [])
    items = "".join(f"<li>{html.escape(str(s))}</li>" for s in steps[:5])
    st.markdown(
        '<div class="box-full"><p class="section-label"><span>🛡</span> Prevention Steps</p>'
        f'<ol class="prevention-list">{items}</ol></div>',
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns(2)
    with col_a:
        tools = res.get("recommended_tools", [])
        t_html = "".join(f"<li>{html.escape(str(t))}</li>" for t in tools[:4])
        st.markdown(
            '<div class="box-full"><p class="section-label"><span>🔧</span> Recommended Tools</p>'
            f'<div class="bullet-tight"><ul>{t_html}</ul></div></div>',
            unsafe_allow_html=True,
        )
    with col_b:
        acts = res.get("immediate_actions", [])
        a_html = "".join(f"<li>{html.escape(str(a))}</li>" for a in acts[:3])
        st.markdown(
            '<div class="box-full"><p class="section-label"><span>⚠</span> Immediate Actions</p>'
            f'<div class="bullet-tight"><ul>{a_html}</ul></div></div>',
            unsafe_allow_html=True,
        )


def main():
    st.set_page_config(
        page_title="Cyber Threat Detector",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_session()
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    st.markdown(
        '<div class="app-hero">'
        '<div class="hero-pulse-bg" aria-hidden="true"></div>'
        '<div class="app-hero-inner">'
        '<div class="hero-top-row">'
        '<span class="hero-shield" aria-hidden="true">🛡</span>'
        '<div class="hero-titles">'
        '<h1 class="hero-line1">Cyber Threat Detector</h1>'
        '<h2 class="hero-line2">Enterprise security intelligence</h2>'
        "</div></div>"
        '<p class="hero-subtext">AI-assisted review of security logs and CSV datasets. Configure the threat lens in the sidebar, '
        "then analyze a single log or an entire file. Results can trigger Telegram alerts when configured.</p>"
        '<div class="hero-pills">'
        '<span class="hero-pill">AI Powered</span>'
        '<span class="hero-pill">Real-time Analysis</span>'
        '<span class="hero-pill">Multi-vector Detection</span>'
        "</div></div></div>",
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown(
            '<div class="sidebar-brand">'
            '<div class="sidebar-title-row">'
            '<p class="sidebar-app-title">Cyber Threat Detector</p>'
            '<span class="sidebar-version">v2.0</span>'
            "</div>"
            '<p class="sidebar-tagline">Gemini-powered analysis · Streamlined workflow</p>'
            "</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            '<p class="sidebar-section-title">Analysis context</p>',
            unsafe_allow_html=True,
        )
        threat_choice = st.selectbox(
            "Threat type",
            options=THREAT_OPTIONS,
            index=0,
            help="Guides the model. Use Auto-Detect when the threat category is unknown.",
        )
        st.caption("Sample logs use this selection when you load demo data.")
        if st.button("Load sample log", use_container_width=True):
            st.session_state.threat_text_area = get_threat_log_sample(threat_choice)
            st.session_state.analysis_result = None
            st.rerun()

    tab_analyze, tab_history = st.tabs(["Threat analysis", "Saved history"])

    with tab_analyze:
        sub_single, sub_csv = st.tabs(["Single log", "CSV dataset"])

        with sub_single:
            st.markdown(
                '<p class="section-label" style="margin-bottom:10px;"><span>⌨</span> Log or narrative input</p>',
                unsafe_allow_html=True,
            )
            st.text_area(
                "Log input",
                height=220,
                key="threat_text_area",
                label_visibility="collapsed",
                placeholder="Paste raw logs, SIEM export snippets, or a short description…",
            )

            if st.button("Run AI analysis", type="primary", use_container_width=False):
                text = (st.session_state.get("threat_text_area") or "").strip()
                if not text:
                    st.warning("Please enter some data to analyze.")
                else:
                    with st.spinner("Analyzing with Gemini AI..."):
                        try:
                            result = analyze_threat(text, threat_choice)
                            st.session_state.analysis_result = result
                            st.session_state.history_refresh += 1
                        except Exception as e:
                            st.error(f"Analysis failed: {e}")
                            st.session_state.analysis_result = None
                            result = None

                    if result is not None:
                        notify_analysis_telegram(result)

            if st.session_state.analysis_result:
                st.markdown("---")
                render_result(st.session_state.analysis_result)

        with sub_csv:
            st.markdown(
                '<p class="section-label" style="margin-bottom:10px;"><span>📊</span> CSV batch review</p>',
                unsafe_allow_html=True,
            )
            st.markdown(
                "<p class='panel-hint'>"
                "Upload your own file or use the bundled example. The model sees dataset statistics plus a sample of rows "
                "(<code>flagged</code> rows first when that column exists). Sidebar threat type still guides interpretation.</p>",
                unsafe_allow_html=True,
            )

            uc1, uc2, uc3 = st.columns([2, 1, 1])
            with uc1:
                uploaded = st.file_uploader(
                    "CSV file",
                    type=["csv"],
                    key="security_csv_uploader",
                    help="Expected columns similar to security_logs_200_points.csv (timestamp, event_type, source_ip, …). Any CSV with log-like columns works.",
                )
            with uc2:
                st.write("")
                st.write("")
                if st.button("Load example CSV", use_container_width=True):
                    ex = BASE_DIR / "security_logs_200_points.csv"
                    if ex.exists():
                        st.session_state.csv_upload_fingerprint = "__bundled_example__"
                        st.session_state.csv_df = read_csv_path(ex)
                        st.session_state.csv_dataset_ai_result = None
                        st.session_state.csv_row_results = None
                        st.success(f"Loaded {len(st.session_state.csv_df)} rows.")
                        st.rerun()
                    else:
                        st.warning("Example file missing in app folder.")
            with uc3:
                st.write("")
                st.write("")
                if st.button("Clear CSV", use_container_width=True):
                    st.session_state.csv_df = None
                    st.session_state.csv_dataset_ai_result = None
                    st.session_state.csv_row_results = None
                    st.session_state.csv_upload_fingerprint = None
                    st.rerun()

            if uploaded is not None:
                fid = f"{uploaded.name}|{uploaded.size}"
                if st.session_state.csv_upload_fingerprint != fid:
                    try:
                        st.session_state.csv_df = read_csv_bytes(uploaded.getvalue())
                        st.session_state.csv_upload_fingerprint = fid
                        st.session_state.csv_dataset_ai_result = None
                        st.session_state.csv_row_results = None
                    except Exception as e:
                        st.error(f"Could not parse CSV: {e}")

            df = st.session_state.csv_df
            if df is None or df.empty:
                st.info("Upload a CSV file or choose **Load example CSV** to preview and analyze.")
            else:
                ok, err_msg = validate_log_dataframe(df)
                if not ok:
                    st.warning(err_msg)
                else:
                    quick = summarize_df_quick(df)
                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.metric("Rows", quick["rows"])
                    with m2:
                        st.metric("Columns", len(quick["columns"]))
                    with m3:
                        fc = quick.get("flagged_count")
                        if fc is not None:
                            st.metric("Flagged rows", fc)
                        else:
                            st.metric("Flagged rows", "—")

                    if quick.get("event_type_counts"):
                        with st.expander("Event type breakdown", expanded=False):
                            st.json(quick["event_type_counts"])

                    st.dataframe(df, use_container_width=True, height=280)

                    st.markdown(
                        '<p class="section-label" style="margin-top:12px;"><span>📈</span> Full-dataset summary</p>',
                        unsafe_allow_html=True,
                    )
                    st.caption(
                        "Single Gemini request over statistics and representative rows. "
                        "Match sidebar threat type to your data, or use Auto-Detect."
                    )
                    if st.button("Analyze full dataset", type="primary", key="btn_csv_full"):
                        ctx = build_dataset_summary_for_ai(df)
                        with st.spinner("Analyzing entire CSV context with Gemini…"):
                            try:
                                res = analyze_threat(ctx, threat_choice, save_history=True)
                                st.session_state.csv_dataset_ai_result = res
                                st.session_state.history_refresh += 1
                            except Exception as e:
                                st.error(f"Analysis failed: {e}")
                                st.session_state.csv_dataset_ai_result = None
                                res = None
                        if res is not None:
                            notify_analysis_telegram(res)

                    if st.session_state.csv_dataset_ai_result:
                        st.markdown("---")
                        render_result(st.session_state.csv_dataset_ai_result)

                    st.markdown(
                        '<p class="section-label" style="margin-top:18px;"><span>🔁</span> Row-by-row analysis (optional)</p>',
                        unsafe_allow_html=True,
                    )
                    max_individual = st.slider(
                        "Number of rows to analyze individually (from the top of the file)",
                        min_value=0,
                        max_value=min(40, len(df)),
                        value=min(5, len(df)),
                        help="Each row is one API call. Use a small number to control cost and time. Telegram is not sent per row.",
                    )
                    if st.button("Run row-by-row analysis", key="btn_csv_rows"):
                        if max_individual < 1:
                            st.warning("Increase the row count above zero to run row-by-row analysis.")
                        else:
                            rows_out: list[dict] = []
                            bar = st.progress(0.0)
                            subset = df.head(max_individual)
                            for i, (_, row) in enumerate(subset.iterrows()):
                                text_row = row_to_security_log_text(row)
                                try:
                                    r = analyze_threat(
                                        text_row,
                                        threat_choice,
                                        save_history=False,
                                    )
                                    rows_out.append(
                                        {
                                            "row": i + 1,
                                            "threat_name": r.get("threat_name", ""),
                                            "category": r.get("threat_category", ""),
                                            "severity": r.get("severity", ""),
                                            "confidence": r.get("confidence", ""),
                                            "is_threat": r.get("is_threat", True),
                                        }
                                    )
                                except Exception as e:
                                    rows_out.append(
                                        {
                                            "row": i + 1,
                                            "threat_name": f"Error: {e}",
                                            "category": "",
                                            "severity": "",
                                            "confidence": "",
                                            "is_threat": True,
                                        }
                                    )
                                bar.progress((i + 1) / max_individual)
                            bar.empty()
                            st.session_state.csv_row_results = rows_out
                            st.success(f"Finished {len(rows_out)} row-level analyses.")

                    if st.session_state.csv_row_results:
                        st.markdown(
                            '<p class="section-label" style="margin-top:8px;"><span>📋</span> Row-level results</p>',
                            unsafe_allow_html=True,
                        )
                        rdf = pd.DataFrame(st.session_state.csv_row_results)
                        st.dataframe(rdf, use_container_width=True, hide_index=True)

    with tab_history:
        st.markdown(
            '<p class="section-label" style="margin-bottom:10px;"><span>🕐</span> Past analyses</p>',
            unsafe_allow_html=True,
        )
        st.caption("Entries are created when analyses are saved to the local history file.")
        history = load_history_raw()
        rows = []
        for entry in history:
            ts = entry.get("saved_at", "")
            r = entry.get("result", {})
            if not r and "results" in entry:
                continue
            rows.append(
                {
                    "Time (UTC)": ts[:19] if ts else "",
                    "Threat": r.get("threat_name", ""),
                    "Category": r.get("threat_category", ""),
                    "Severity": r.get("severity", ""),
                    "Confidence": r.get("confidence", ""),
                }
            )
        if not rows:
            st.info("No saved analyses yet. Run a threat analysis on the **Threat analysis** tab.")
        else:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
        if st.button("Clear saved history", type="secondary"):
            clear_history_file()
            st.success("History cleared.")
            st.rerun()

    st.markdown(
        '<div class="app-footer">'
        "Cyber Threat Detector · Powered by Gemini AI · Built with Streamlit"
        "</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
