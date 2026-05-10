"""
Cloud-deployable proxy server for the Expense Anomaly Agent.

Differences from the local version:
  * Configuration comes from environment variables (HOST, PORT, GROQ_API_KEY,
    DATABASE_URL, DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD).
  * Auth (users) and rules persist in Postgres instead of local JSON files,
    so they survive container restarts on Render's ephemeral filesystem.
  * Binds to 0.0.0.0 so the platform can route traffic to it.
  * Default admin password is generated/seeded on first run from env vars.

Required env vars:
  GROQ_API_KEY          - Groq API key (https://console.groq.com)
  DATABASE_URL          - Postgres connection string from Neon/Supabase/etc.
                          Format: postgresql://user:pass@host/dbname?sslmode=require

Optional env vars:
  PORT                  - Port to bind to (default 8765; Render sets this for you)
  HOST                  - Host to bind to (default 0.0.0.0)
  DEFAULT_ADMIN_USERNAME - Username for the seeded admin (default 'admin')
  DEFAULT_ADMIN_PASSWORD - Password for the seeded admin (default 'admin').
                           IMPORTANT: change in Render's env settings before first deploy.
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

# ---------- env-driven config ----------
ROOT = Path(__file__).parent
WEB_DIR = ROOT / "web"
ARTIFACT = WEB_DIR / "artifact.html"

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8765"))

LLM_MODEL = os.environ.get("LLM_MODEL", "openai/gpt-oss-120b")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.groq.com/openai/v1")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin")

# session config
SESSION_TTL_SECONDS = 8 * 3600
LOGIN_LOCKOUT_AFTER = 5
LOGIN_LOCKOUT_SECONDS = 5 * 60

# ---------- shared state ----------
_client_lock = threading.Lock()
_client = None
_auth_lock = threading.Lock()
_sessions: dict[str, dict] = {}
_failures: dict[str, list] = {}


def get_client():
    """Lazy-construct the OpenAI-compatible client (Groq)."""
    global _client
    with _client_lock:
        if _client is None:
            from openai import OpenAI
            key = os.environ.get("GROQ_API_KEY")
            if not key:
                raise RuntimeError("GROQ_API_KEY env var is not set")
            _client = OpenAI(api_key=key, base_url=LLM_BASE_URL)
        return _client


# =============================================================
# Storage layer: Postgres
# =============================================================

USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username             TEXT PRIMARY KEY,
    salt                 TEXT NOT NULL,
    password_hash        TEXT NOT NULL,
    is_admin             BOOLEAN NOT NULL DEFAULT FALSE,
    is_researcher        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           BIGINT NOT NULL,
    password_changed_at  BIGINT
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_researcher BOOLEAN NOT NULL DEFAULT FALSE;
"""

RULES_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id          INT PRIMARY KEY DEFAULT 1,
    data        JSONB NOT NULL,
    updated_at  BIGINT NOT NULL,
    CHECK (id = 1)
);
"""

# Algorithm config: which detector is active, sensitivity, group assignments.
# Hidden from employees and auditors (they only see "Algorithm sensitivity").
ALGO_SCHEMA = """
CREATE TABLE IF NOT EXISTS algorithm_config (
    id          INT PRIMARY KEY DEFAULT 1,
    data        JSONB NOT NULL,
    updated_at  BIGINT NOT NULL,
    CHECK (id = 1)
);
"""

# Audit events: log of rule changes, overrides, treatment applications.
EVENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at BIGINT NOT NULL,
    event_type  TEXT NOT NULL,
    actor       TEXT,
    target      TEXT,
    payload     JSONB
);
CREATE INDEX IF NOT EXISTS audit_events_occurred_at_idx ON audit_events (occurred_at);
CREATE INDEX IF NOT EXISTS audit_events_type_idx ON audit_events (event_type);
"""

# Treatment assignments
TREATMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS treatments (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    rule_payload  JSONB NOT NULL,
    target_group  JSONB NOT NULL,
    started_at    BIGINT NOT NULL,
    ended_at      BIGINT,
    notes         TEXT
);
"""

# Documents (receipts, invoices)
DOCUMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id              BIGSERIAL PRIMARY KEY,
    transaction_id  TEXT NOT NULL,
    uploaded_by     TEXT NOT NULL,
    uploaded_at     BIGINT NOT NULL,
    filename        TEXT NOT NULL,
    mime_type       TEXT NOT NULL,
    size_bytes      INT NOT NULL,
    extracted_text  TEXT,
    contents        BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS documents_txn_idx ON documents (transaction_id);
"""


def get_conn():
    """Open a new Postgres connection. Each request opens its own."""
    import psycopg
    from psycopg.rows import dict_row
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL env var is not set")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(USERS_SCHEMA)
            cur.execute(RULES_SCHEMA)
            cur.execute(ALGO_SCHEMA)
            cur.execute(EVENTS_SCHEMA)
            cur.execute(TREATMENTS_SCHEMA)
            cur.execute(DOCUMENTS_SCHEMA)
        conn.commit()


def db_load_users() -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, salt, password_hash AS hash, is_admin, is_researcher, "
                "created_at, password_changed_at FROM users ORDER BY username"
            )
            return [dict(r) for r in cur.fetchall()]


def db_count_users() -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM users")
            return cur.fetchone()["n"]


def db_replace_users(users: list[dict]) -> None:
    """Atomically replace the users table with the given list."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users")
            for u in users:
                cur.execute(
                    "INSERT INTO users (username, salt, password_hash, is_admin, is_researcher, "
                    "created_at, password_changed_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (u["username"], u["salt"], u["hash"],
                     bool(u.get("is_admin")), bool(u.get("is_researcher")),
                     int(u.get("created_at") or time.time()),
                     u.get("password_changed_at")),
                )
        conn.commit()


def db_load_rules() -> dict | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT data FROM rules WHERE id = 1")
            row = cur.fetchone()
            return row["data"] if row else None


def db_save_rules(data: dict) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rules (id, data, updated_at) VALUES (1, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
                (json.dumps(data), int(time.time())),
            )
        conn.commit()


# =============================================================
# Auth: PBKDF2 password hashing + in-memory sessions
# =============================================================

def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
    ).hex()


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_hash_password(password, salt), expected_hash)


def _new_user_record(username: str, password: str, is_admin: bool, is_researcher: bool = False) -> dict:
    salt = secrets.token_hex(16)
    return {
        "username": username,
        "salt": salt,
        "hash": _hash_password(password, salt),
        "is_admin": bool(is_admin),
        "is_researcher": bool(is_researcher),
        "created_at": int(time.time()),
        "password_changed_at": None,
    }


def seed_default_admin_if_no_users() -> bool:
    """If the users table is empty, create the bundled admin from env vars.
    Returns True iff an admin was seeded."""
    with _auth_lock:
        if db_count_users() > 0:
            return False
        admin = _new_user_record(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, is_admin=True)
        db_replace_users([admin])
        return True


def load_auth() -> dict:
    return {"users": db_load_users()}


def save_auth(rec: dict) -> None:
    db_replace_users(rec.get("users", []))


def find_user(rec: dict, username: str) -> dict | None:
    for u in rec.get("users", []):
        if u.get("username", "").lower() == username.lower():
            return u
    return None


def admin_count(rec: dict) -> int:
    return sum(1 for u in rec.get("users", []) if u.get("is_admin"))


def any_default_password_still_used(rec: dict) -> bool:
    for u in rec.get("users", []):
        if u.get("is_admin") and u.get("password_changed_at") is None:
            return True
    return False


def issue_session(username: str, is_admin: bool, is_researcher: bool = False) -> tuple[str, float]:
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + SESSION_TTL_SECONDS
    _sessions[token] = {
        "username": username,
        "is_admin": bool(is_admin),
        "is_researcher": bool(is_researcher),
        "expires_at": expires_at,
    }
    return token, expires_at


def revoke_session(token: str) -> None:
    _sessions.pop(token, None)


def session_info(token: str | None) -> dict | None:
    if not token:
        return None
    s = _sessions.get(token)
    if s is None:
        return None
    if s["expires_at"] < time.time():
        _sessions.pop(token, None)
        return None
    return s


def is_session_valid(token: str | None) -> bool:
    return session_info(token) is not None


def is_locked_out(ip: str) -> tuple[bool, int]:
    cutoff = time.time() - LOGIN_LOCKOUT_SECONDS
    fails = [t for t in _failures.get(ip, []) if t > cutoff]
    _failures[ip] = fails
    if len(fails) >= LOGIN_LOCKOUT_AFTER:
        retry = int(fails[0] + LOGIN_LOCKOUT_SECONDS - time.time())
        return True, max(1, retry)
    return False, 0


def record_login_failure(ip: str) -> None:
    _failures.setdefault(ip, []).append(time.time())


def reset_failures(ip: str) -> None:
    _failures.pop(ip, None)


# =============================================================
# Rules
# =============================================================

DEFAULT_RULES = {
    "z_threshold": 2.0,
    "policy_text": (
        "Pre-approval is required for any single expense above $2,500. "
        "Conference and training expenses must reference an approved training plan or PO. "
        "Marketing spend must align with the documented quarterly campaign plan. "
        "Any explanation that cites 'personal', 'forgot', 'unaware', or 'mistake' should be RED. "
        "Vendor must be consistent with the GL category - e.g. an Office Supplies vendor cannot be "
        "justified as a Marketing campaign."
    ),
    "auto_red_keywords": [
        "personal", "forgot", "unaware", "mistake", "no reason",
        "didn't realize", "did not realize", "didn't know",
    ],
    "auto_green_keywords": [
        "pre-approved by cfo", "pre-approved by cto", "pre-approved by ceo",
        "annual contract", "emergency replacement", "po #", "purchase order",
        "receipt attached", "concur", "training plan",
    ],
    "category_caps": [
        {"category": "Travel",                "soft_cap": 1500, "hard_cap": 5000},
        {"category": "Office Supplies",       "soft_cap": 250,  "hard_cap": 750},
        {"category": "Software/SaaS",         "soft_cap": 1200, "hard_cap": 5000},
        {"category": "Marketing",             "soft_cap": 3000, "hard_cap": 10000},
        {"category": "Consulting",            "soft_cap": 8000, "hard_cap": 25000},
        {"category": "Equipment",             "soft_cap": 3500, "hard_cap": 12000},
        {"category": "Meals & Entertainment", "soft_cap": 200,  "hard_cap": 500},
        {"category": "Utilities",             "soft_cap": 600,  "hard_cap": 1500},
    ],
    "wizard_max_turns": 6,
}


def load_rules() -> dict:
    data = db_load_rules()
    if data is None:
        # seed defaults on first run
        db_save_rules(DEFAULT_RULES)
        return dict(DEFAULT_RULES)
    # backfill any missing keys so the schema can evolve
    for k, v in DEFAULT_RULES.items():
        data.setdefault(k, v)
    return data


def save_rules(rules: dict) -> dict:
    cleaned = dict(DEFAULT_RULES)
    cleaned.update({k: v for k, v in rules.items() if k in DEFAULT_RULES})
    try:
        cleaned["z_threshold"] = max(1.0, min(5.0, float(cleaned.get("z_threshold", 2.0))))
    except Exception:
        cleaned["z_threshold"] = 2.0
    try:
        cleaned["wizard_max_turns"] = max(2, min(10, int(cleaned.get("wizard_max_turns", 6))))
    except Exception:
        cleaned["wizard_max_turns"] = 6
    if not isinstance(cleaned.get("auto_red_keywords"), list):
        cleaned["auto_red_keywords"] = []
    if not isinstance(cleaned.get("auto_green_keywords"), list):
        cleaned["auto_green_keywords"] = []
    cleaned["auto_red_keywords"] = [str(k).strip().lower() for k in cleaned["auto_red_keywords"] if str(k).strip()]
    cleaned["auto_green_keywords"] = [str(k).strip().lower() for k in cleaned["auto_green_keywords"] if str(k).strip()]
    if not isinstance(cleaned.get("category_caps"), list):
        cleaned["category_caps"] = []
    cleaned["policy_text"] = str(cleaned.get("policy_text", ""))[:8000]
    db_save_rules(cleaned)
    return cleaned


# =============================================================
# Algorithm config (researcher-controlled, hidden from others)
# =============================================================
AVAILABLE_ALGORITHMS = [
    {"id": "z_score",          "name": "Z-Score (per category)",
     "param_label": "Threshold (sigma)", "min": 1.0, "max": 5.0, "step": 0.1, "default": 2.0,
     "description": "Flags transactions whose amount is more than N standard deviations above their category mean. Classic but assumes a normal distribution and is sensitive to its own outliers."},
    {"id": "log_z",            "name": "Log Z-Score",
     "param_label": "Threshold (sigma on log scale)", "min": 1.0, "max": 5.0, "step": 0.1, "default": 2.0,
     "description": "Z-score on log(amount). Robust to right-skewed expense distributions; recommended over plain z-score for monetary data."},
    {"id": "mad",              "name": "Modified Z-Score (MAD)",
     "param_label": "Threshold (MAD units)", "min": 2.0, "max": 6.0, "step": 0.1, "default": 3.5,
     "description": "Uses median and median absolute deviation. Resistant to outlier contamination of the threshold itself."},
    {"id": "iqr",              "name": "IQR / Tukey fences",
     "param_label": "IQR multiplier", "min": 0.5, "max": 3.0, "step": 0.1, "default": 1.5,
     "description": "Flags amounts above Q3 + N x IQR. Distribution-free, classic boxplot rule."},
    {"id": "per_requester_z",  "name": "Per-requester baseline",
     "param_label": "Threshold (sigma vs own history)", "min": 1.0, "max": 5.0, "step": 0.1, "default": 2.0,
     "description": "Compares each transaction to the requester's own historical pattern, not the category-wide mean. Catches behavioural shifts global stats miss."},
]

DEFAULT_ALGORITHM_CONFIG = {
    "active": "z_score",
    "sensitivity": 2.0,
}


def db_load_algorithm_config() -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT data FROM algorithm_config WHERE id = 1")
            row = cur.fetchone()
            return row["data"] if row else None


def db_save_algorithm_config(data: dict) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO algorithm_config (id, data, updated_at) VALUES (1, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
                (json.dumps(data), int(time.time())),
            )
        conn.commit()


def load_algorithm_config() -> dict:
    data = db_load_algorithm_config()
    if data is None:
        db_save_algorithm_config(DEFAULT_ALGORITHM_CONFIG)
        return dict(DEFAULT_ALGORITHM_CONFIG)
    for k, v in DEFAULT_ALGORITHM_CONFIG.items():
        data.setdefault(k, v)
    return data


def save_algorithm_config(data: dict) -> dict:
    active = str(data.get("active") or "z_score").strip()
    if not any(a["id"] == active for a in AVAILABLE_ALGORITHMS):
        active = "z_score"
    algo = next(a for a in AVAILABLE_ALGORITHMS if a["id"] == active)
    try:
        sens = float(data.get("sensitivity", algo["default"]))
    except Exception:
        sens = algo["default"]
    sens = max(algo["min"], min(algo["max"], sens))
    cleaned = {"active": active, "sensitivity": sens}
    db_save_algorithm_config(cleaned)
    return cleaned


# =============================================================
# Audit events (for researcher analytics)
# =============================================================
def log_event(event_type: str, actor: str | None, target: str | None, payload: dict | None = None) -> None:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO audit_events (occurred_at, event_type, actor, target, payload) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (int(time.time()), event_type, actor, target,
                     json.dumps(payload or {})),
                )
            conn.commit()
    except Exception as e:
        print(f"[events] failed to log {event_type}: {e}", flush=True)


def db_recent_events(limit: int = 500) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, occurred_at, event_type, actor, target, payload "
                "FROM audit_events ORDER BY occurred_at DESC LIMIT %s", (limit,)
            )
            return [dict(r) for r in cur.fetchall()]


# =============================================================
# Treatments (researcher / auditor experimental rule deployment)
# =============================================================
def db_load_treatments() -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, rule_payload, target_group, started_at, ended_at, notes "
                "FROM treatments ORDER BY started_at DESC"
            )
            return [dict(r) for r in cur.fetchall()]


def db_create_treatment(name: str, rule_payload: dict, target_group: dict, notes: str = "") -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO treatments (name, rule_payload, target_group, started_at, notes) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (name, json.dumps(rule_payload), json.dumps(target_group),
                 int(time.time()), notes),
            )
            new_id = cur.fetchone()["id"]
        conn.commit()
        return new_id


def db_end_treatment(treatment_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE treatments SET ended_at = %s WHERE id = %s",
                (int(time.time()), treatment_id),
            )
        conn.commit()


# =============================================================
# Documents
# =============================================================
def db_save_document(transaction_id: str, uploaded_by: str, filename: str,
                     mime_type: str, contents: bytes, extracted_text: str | None) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO documents (transaction_id, uploaded_by, uploaded_at, filename, "
                "mime_type, size_bytes, extracted_text, contents) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (transaction_id, uploaded_by, int(time.time()), filename,
                 mime_type, len(contents), extracted_text, contents),
            )
            new_id = cur.fetchone()["id"]
        conn.commit()
        return new_id


def db_list_documents(transaction_id: str | None = None) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            if transaction_id:
                cur.execute(
                    "SELECT id, transaction_id, uploaded_by, uploaded_at, filename, mime_type, "
                    "size_bytes, extracted_text FROM documents WHERE transaction_id = %s "
                    "ORDER BY uploaded_at DESC",
                    (transaction_id,),
                )
            else:
                cur.execute(
                    "SELECT id, transaction_id, uploaded_by, uploaded_at, filename, mime_type, "
                    "size_bytes, extracted_text FROM documents ORDER BY uploaded_at DESC LIMIT 200"
                )
            return [dict(r) for r in cur.fetchall()]


def seed_demo_data() -> dict:
    """Seed the database with a realistic 6-month timeline of audit events,
    treatments, and a charter-school student roster. Safe to re-run.
    Returns counts of what was inserted."""
    import random
    rng = random.Random(13)
    now = int(time.time())
    six_months = 180 * 86400
    inserted = {"events": 0, "treatments": 0, "rosters": 0}

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Roster table: very small dim table for institutional indicators
            cur.execute("""
                CREATE TABLE IF NOT EXISTS student_roster (
                    department      TEXT PRIMARY KEY,
                    program_label   TEXT NOT NULL,
                    student_count   INT NOT NULL,
                    direct_instruction_share REAL NOT NULL
                );
            """)
            # Each "department" in the mock txns maps to a school program with headcount.
            roster = [
                ("Engineering",  "STEM after-school program",   320, 0.62),
                ("Sales",        "Family engagement",            18, 0.05),
                ("Marketing",    "Community outreach",           24, 0.08),
                ("Finance",      "Operations - admin",           12, 0.00),
                ("Operations",   "Facilities - admin",           36, 0.10),
                ("HR",           "Staff development",            22, 0.20),
            ]
            for r in roster:
                cur.execute(
                    "INSERT INTO student_roster (department, program_label, student_count, direct_instruction_share) "
                    "VALUES (%s,%s,%s,%s) ON CONFLICT (department) DO UPDATE SET "
                    "program_label = EXCLUDED.program_label, student_count = EXCLUDED.student_count, "
                    "direct_instruction_share = EXCLUDED.direct_instruction_share",
                    r,
                )
                inserted["rosters"] += 1

            # Don't double-seed events
            cur.execute("SELECT COUNT(*) AS n FROM audit_events WHERE event_type IN ('override','rule_change','treatment_created','document_upload')")
            existing_events = cur.fetchone()["n"]
            if existing_events > 50:
                conn.commit()
                return {**inserted, "skipped_events": existing_events}

            # 1. Rule-change events (3-4 across the 6 months)
            rule_events = [
                (now - int(six_months * 0.85), "Tightened auto-RED phrases (+'no reason')"),
                (now - int(six_months * 0.55), "Added Marketing $3K hard cap"),
                (now - int(six_months * 0.30), "Required PO# for Consulting > $10K"),
                (now - int(six_months * 0.10), "Added wizard step for Equipment > $5K"),
            ]
            for ts, label in rule_events:
                cur.execute(
                    "INSERT INTO audit_events (occurred_at, event_type, actor, target, payload) VALUES (%s,%s,%s,%s,%s)",
                    (ts, "rule_change", "admin", "policy_text", json.dumps({"label": label})),
                )
                inserted["events"] += 1

            # 2. Override events - auditor overrides employee classifications
            requesters = ["Alice Chen","Bob Martinez","Carol Davis","Devon Patel","Erin O'Brien","Frank Lee","Grace Kim","Hugo Bauer"]
            departments = ["Engineering","Sales","Marketing","Finance","Operations","Engineering","HR","Sales"]
            categories  = ["Travel","Software/SaaS","Marketing","Office Supplies","Consulting","Equipment","Meals & Entertainment","Utilities"]
            for i in range(80):
                ts = now - rng.randint(0, six_months)
                req_idx = rng.randint(0, len(requesters) - 1)
                req = requesters[req_idx]
                dept = departments[req_idx]
                cat = rng.choice(categories)
                # different baseline override rates per category/requester so the analytics see signal
                from_flag = rng.choice(["RED","RED","RED","YELLOW","GREEN"])
                to_flag = rng.choice(["YELLOW","GREEN","RED"])
                if from_flag == to_flag:
                    to_flag = "GREEN" if from_flag == "RED" else "RED"
                cur.execute(
                    "INSERT INTO audit_events (occurred_at, event_type, actor, target, payload) VALUES (%s,%s,%s,%s,%s)",
                    (ts, "override", "auditor1", f"TXN{100000 + i}",
                     json.dumps({"from": from_flag, "to": to_flag, "requester": req,
                                 "department": dept, "category": cat,
                                 "amount": round(rng.uniform(200, 8000), 2),
                                 "note": "Documented override during audit cycle."})),
                )
                inserted["events"] += 1

            # 3. Wizard classifications (mix of GREEN/YELLOW/RED with employee + dept context)
            for i in range(120):
                ts = now - rng.randint(0, six_months)
                req_idx = rng.randint(0, len(requesters) - 1)
                cat = rng.choice(categories)
                flag = rng.choices(["GREEN","YELLOW","RED"], weights=[0.55, 0.25, 0.20])[0]
                cur.execute(
                    "INSERT INTO audit_events (occurred_at, event_type, actor, target, payload) VALUES (%s,%s,%s,%s,%s)",
                    (ts, "wizard_classification", requesters[req_idx], f"TXN{100200 + i}",
                     json.dumps({"flag": flag, "requester": requesters[req_idx],
                                 "department": departments[req_idx], "category": cat,
                                 "amount": round(rng.uniform(150, 12000), 2)})),
                )
                inserted["events"] += 1

            # 4. Document uploads
            for i in range(40):
                ts = now - rng.randint(0, six_months)
                req_idx = rng.randint(0, len(requesters) - 1)
                cur.execute(
                    "INSERT INTO audit_events (occurred_at, event_type, actor, target, payload) VALUES (%s,%s,%s,%s,%s)",
                    (ts, "document_upload", requesters[req_idx], f"TXN{100300 + i}",
                     json.dumps({"filename": f"receipt_{i}.pdf", "mime": "application/pdf",
                                 "size": rng.randint(40_000, 800_000), "has_text": rng.random() > 0.3})),
                )
                inserted["events"] += 1

            # 5. Treatments - 3 experimental rule deployments with known target groups
            treatments = [
                ("Q2 Marketing pre-approval pilot",
                 {"policy_text_addition": "Marketing > $2K requires CFO sign-off."},
                 {"departments": ["Marketing"]},
                 now - int(six_months * 0.40),
                 "Pilot to test whether stricter pre-approval reduces marketing overruns."),
                ("Random 50% Equipment cap test",
                 {"new_category_caps": [{"category": "Equipment", "soft_cap": 2000, "hard_cap": 6000}]},
                 {"random_pct": 50, "seed": 42},
                 now - int(six_months * 0.20),
                 "Randomly half of all requesters for parallel-trends analysis."),
                ("Sales travel guardrails",
                 {"new_auto_red_keywords": ["upgrade","rebooked","resort"]},
                 {"departments": ["Sales"]},
                 now - int(six_months * 0.10),
                 "Targets specific phrases known to correlate with policy violations."),
            ]
            for name, rule, tgt, started, note in treatments:
                cur.execute(
                    "INSERT INTO treatments (name, rule_payload, target_group, started_at, notes) "
                    "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (name, json.dumps(rule), json.dumps(tgt), started, note),
                )
                tid = cur.fetchone()["id"]
                inserted["treatments"] += 1
                # also log a treatment_created event so it shows in event_study
                cur.execute(
                    "INSERT INTO audit_events (occurred_at, event_type, actor, target, payload) VALUES (%s,%s,%s,%s,%s)",
                    (started, "treatment_created", "researcher1", str(tid),
                     json.dumps({"name": name, "rule_payload": rule, "target_group": tgt})),
                )
                inserted["events"] += 1

        conn.commit()
    return inserted


def db_load_roster() -> list[dict]:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT department, program_label, student_count, direct_instruction_share FROM student_roster")
                return [dict(r) for r in cur.fetchall()]
    except Exception:
        return []


def db_get_document(doc_id: int) -> dict | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, transaction_id, filename, mime_type, contents FROM documents WHERE id = %s",
                (doc_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def extract_text_from_pdf_bytes(data: bytes) -> str | None:
    """Best-effort text extraction from PDF bytes. Returns None if pypdf
    isn't installed or extraction fails."""
    try:
        from pypdf import PdfReader
        from io import BytesIO
        reader = PdfReader(BytesIO(data))
        chunks = []
        for page in reader.pages[:20]:  # cap at 20 pages
            chunks.append(page.extract_text() or "")
        text = "\n".join(chunks).strip()
        return text[:8000] if text else None
    except Exception:
        return None


# =============================================================
# Public/auth gating
# =============================================================
PUBLIC_PATHS = {
    ("GET",  "/"),
    ("GET",  "/index.html"),
    ("GET",  "/artifact.html"),
    ("GET",  "/api/health"),
    ("GET",  "/api/auth-status"),
    ("POST", "/api/login"),
}


# =============================================================
# Wizard prompt builders
# =============================================================
def _wizard_system_prompt(txn: dict, rules: dict, max_turns: int, turns_used: int, force_conclude: bool) -> str:
    caps_lines = "\n".join(
        f"  - {c.get('category')}: soft cap ${c.get('soft_cap')}, hard cap ${c.get('hard_cap')}"
        for c in (rules.get("category_caps") or [])
    ) or "  (none configured)"
    auto_red = ", ".join(rules.get("auto_red_keywords") or []) or "(none)"
    auto_green = ", ".join(rules.get("auto_green_keywords") or []) or "(none)"
    policy = (rules.get("policy_text") or "").strip() or "(no additional policy)"

    base = f"""You are an internal-controls reviewer interviewing an employee whose expense was \
flagged. Your job is to ask the SHORTEST sequence of questions that will let you \
assign the expense GREEN, YELLOW, or RED according to the company's policy below. \
Stay focused; do not ramble.

Transaction under review:
  ID:       {txn.get('transaction_id', '?')}
  Date:     {txn.get('date', '?')}
  Vendor:   {txn.get('vendor', '?')}
  Category: {txn.get('category', '?')}
  Amount:   ${float(txn.get('amount', 0)):,.2f}  (category mean ${float(txn.get('cat_mean', 0)):,.2f}, +{float(txn.get('deviation_pct', 0)):.0f}%)
  Requester: {txn.get('requester', '?')} ({txn.get('department', '?')})

Company policy:
{policy}

Per-category caps:
{caps_lines}

Auto-RED phrases (if the user's answers reveal these patterns, lean RED):
  {auto_red}

Auto-GREEN phrases (clear approval/documentation references that lean GREEN):
  {auto_green}

Rules of the interview:
1. Maximum {max_turns} questions. You have used {turns_used}.
2. Ask ONE question per turn. Prefer multiple-choice when there are clear options; \
use open questions only when the auditor really needs free text (vendor names, PO numbers, etc).
3. Each question must move you closer to a decision. Do not ask about things you already know.
4. If the user gives vague, evasive, or unhelpful answers two turns in a row, conclude \
with action=conclude and needs_human=true (do NOT guess).
5. If the user has clearly satisfied the policy, conclude GREEN. If clearly violated, conclude RED. \
If partial / unverified, YELLOW.
6. NEVER hallucinate that approvals exist. Confirmation requires the user to say so explicitly.
"""
    if force_conclude:
        base += "\nIMPORTANT: You have reached the question cap. You MUST set action=\"conclude\" this turn.\n"

    base += """
Reply with ONLY a single JSON object (no prose, no code fences). Two valid shapes:

  Ask next question:
    {"action":"ask","question":"...","type":"open"}
    {"action":"ask","question":"...","type":"select","options":["...","...","..."]}

  Conclude with classification:
    {"action":"conclude","flag":"GREEN|YELLOW|RED","rationale":"<one sentence>","needs_human":false}
    {"action":"conclude","flag":"YELLOW","rationale":"<why escalate>","needs_human":true}
"""
    return base


def _rule_wizard_ask_prompt(strategy: str, history: list, current_rules: dict) -> str:
    history_text = "\n".join(
        f"Q{i+1}: {h.get('question','')}\nA{i+1}: {h.get('answer','')}"
        for i, h in enumerate(history)
    ) or "(no answers yet)"
    return f"""You are helping an internal auditor design a new expense business rule.

The auditor described their strategy / concern:
\"\"\"{strategy}\"\"\"

Conversation so far:
{history_text}

Current rules in effect:
- Policy text: {current_rules.get('policy_text','')[:500]}
- Auto-RED phrases: {', '.join(current_rules.get('auto_red_keywords', [])) or '(none)'}
- Auto-GREEN phrases: {', '.join(current_rules.get('auto_green_keywords', [])) or '(none)'}

Ask ONE concise clarifying question that will help you craft a precise rule. \
Prefer multiple-choice when there are clear options. After 3-4 questions you \
should have enough to propose a rule. If you have enough information now, set \
action=ready instead of asking another question.

Reply with ONLY a JSON object:
  {{"action":"ask","question":"...","type":"open"}}
  {{"action":"ask","question":"...","type":"select","options":["...","..."]}}
  {{"action":"ready"}}
"""


def _rule_wizard_propose_prompt(strategy: str, history: list, current_rules: dict) -> str:
    history_text = "\n".join(
        f"Q: {h.get('question','')}\nA: {h.get('answer','')}"
        for h in history
    ) or "(no specifics)"
    return f"""You are an internal-controls policy author. Based on the auditor's strategy \
and the answers below, propose a concrete addition to the current ruleset.

Auditor's strategy:
\"\"\"{strategy}\"\"\"

Auditor's answers:
{history_text}

Current ruleset (for context, do not duplicate):
{json.dumps(current_rules, indent=2)[:1500]}

Output a JSON object describing the new rule additions. Only include fields \
that change. Allowed top-level keys:
  - policy_text_addition: a short paragraph to append to policy_text
  - new_auto_red_keywords: list of phrases to add
  - new_auto_green_keywords: list of phrases to add
  - new_category_caps: list of {{category, soft_cap, hard_cap}}
  - rationale: one short sentence explaining what this rule catches

Reply with ONLY a JSON object, no prose, no code fences. Example shape:
{{"policy_text_addition":"...","new_auto_red_keywords":["..."],"rationale":"..."}}
"""


def _wizard_user_prompt(history: list) -> str:
    if not history:
        return "Begin the interview. Ask the first question."
    lines = ["Conversation so far:\n"]
    for i, t in enumerate(history, 1):
        q = (t.get("question") or "").strip()
        a = (t.get("answer") or "").strip()
        lines.append(f"Q{i}: {q}\nA{i}: {a if a else '(no answer)'}\n")
    lines.append("Decide your next move per the rules above.")
    return "\n".join(lines)


# =============================================================
# HTTP handler
# =============================================================
class Handler(http.server.BaseHTTPRequestHandler):

    # ---- auth helpers -----------------------------------------

    def _bearer_token(self) -> str | None:
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h[7:].strip()
        return None

    def _client_ip(self) -> str:
        # Behind a Render proxy, the real IP is in X-Forwarded-For
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "?"

    def _require_auth(self) -> bool:
        if is_session_valid(self._bearer_token()):
            return True
        self._json(401, {"error": "authentication required"})
        return False

    def _require_admin(self) -> bool:
        s = session_info(self._bearer_token())
        if s and s.get("is_admin"):
            return True
        self._json(403, {"error": "admin privileges required"})
        return False

    def _require_researcher(self) -> bool:
        s = session_info(self._bearer_token())
        if s and (s.get("is_researcher") or s.get("is_admin")):
            return True
        self._json(403, {"error": "researcher privileges required"})
        return False

    # ---- routing -----------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path
        if ("GET", path) not in PUBLIC_PATHS and not self._require_auth():
            return
        if path in ("/", "/index.html", "/artifact.html"):
            self._serve_file(ARTIFACT, "text/html; charset=utf-8")
        elif path == "/api/health":
            self._json(200, {"ok": True, "model": LLM_MODEL, "provider": "groq"})
        elif path == "/api/auth-status":
            tok = self._bearer_token()
            s = session_info(tok)
            payload = {"authenticated": s is not None}
            if s:
                payload["username"] = s["username"]
                payload["is_admin"] = s["is_admin"]
                payload["is_researcher"] = s.get("is_researcher", False)
                payload["expires_at"] = s["expires_at"]
            try:
                rec = load_auth()
                payload["default_password_in_use"] = any_default_password_still_used(rec)
            except Exception:
                payload["default_password_in_use"] = False
            self._json(200, payload)
        elif path == "/api/rules":
            self._json(200, load_rules())
        elif path == "/api/users":
            if not self._require_admin():
                return
            rec = load_auth()
            users = [{
                "username": u["username"],
                "is_admin": bool(u.get("is_admin")),
                "is_researcher": bool(u.get("is_researcher")),
                "created_at": u.get("created_at"),
                "password_changed_at": u.get("password_changed_at"),
            } for u in rec.get("users", [])]
            self._json(200, {"users": users})
        elif path == "/api/algorithm":
            # Authed; returns the active algorithm. Researchers also get the
            # full catalog of available algorithms. Auditors/employees get
            # only the sensitivity slider info, NOT the algorithm name.
            cfg = load_algorithm_config()
            s = session_info(self._bearer_token())
            algo = next((a for a in AVAILABLE_ALGORITHMS if a["id"] == cfg["active"]), AVAILABLE_ALGORITHMS[0])
            payload = {
                "active": cfg["active"],
                "sensitivity": cfg["sensitivity"],
                "min": algo["min"], "max": algo["max"], "step": algo["step"],
                "default": algo["default"],
            }
            if s and (s.get("is_researcher") or s.get("is_admin")):
                payload["researcher_view"] = True
                payload["available"] = AVAILABLE_ALGORITHMS
                payload["algo_id"] = algo["id"]
                payload["algo_name"] = algo["name"]
                payload["algo_description"] = algo["description"]
                payload["param_label"] = algo["param_label"]
            else:
                payload["researcher_view"] = False
                payload["param_label"] = "Algorithm sensitivity"
            self._json(200, payload)
        elif path == "/api/documents":
            # list docs for one transaction (or recent globally for the auditor)
            from urllib.parse import parse_qs
            q = parse_qs(urlparse(self.path).query)
            txn = (q.get("transaction_id", [None]) or [None])[0]
            self._json(200, {"documents": db_list_documents(txn)})
        elif path.startswith("/api/documents/") and not path.endswith("/raw"):
            # metadata for one doc
            try:
                doc_id = int(path[len("/api/documents/"):])
            except ValueError:
                return self.send_error(404)
            doc = db_get_document(doc_id)
            if not doc:
                return self.send_error(404)
            self._json(200, {"id": doc["id"], "transaction_id": doc["transaction_id"],
                             "filename": doc["filename"], "mime_type": doc["mime_type"]})
        elif path.startswith("/api/documents/") and path.endswith("/raw"):
            # raw bytes for a document (for auditor preview)
            try:
                doc_id = int(path[len("/api/documents/"):-len("/raw")])
            except ValueError:
                return self.send_error(404)
            doc = db_get_document(doc_id)
            if not doc:
                return self.send_error(404)
            body = bytes(doc["contents"])
            self.send_response(200)
            self.send_header("Content-Type", doc["mime_type"] or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'inline; filename="{doc["filename"]}"')
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/events":
            # researcher-only: full event log
            if not self._require_researcher():
                return
            from urllib.parse import parse_qs
            q = parse_qs(urlparse(self.path).query)
            limit = int((q.get("limit", ["500"]) or ["500"])[0])
            self._json(200, {"events": db_recent_events(min(limit, 5000))})
        elif path == "/api/treatments":
            if not self._require_researcher():
                return
            self._json(200, {"treatments": db_load_treatments()})
        elif path == "/api/roster":
            self._json(200, {"roster": db_load_roster()})
        else:
            try:
                target = (WEB_DIR / path.lstrip("/")).resolve()
                if WEB_DIR.resolve() in target.parents and target.is_file():
                    self._serve_file(target, _ctype(target))
                    return
            except Exception:
                pass
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        if ("POST", path) not in PUBLIC_PATHS and not self._require_auth():
            return
        if path == "/api/login":
            self._login()
        elif path == "/api/logout":
            self._logout()
        elif path == "/api/change-password":
            self._change_password()
        elif path == "/api/users":
            if self._require_admin():
                self._create_user()
        elif path.startswith("/api/users/") and path.endswith("/password"):
            if self._require_admin():
                username = path[len("/api/users/"):-len("/password")]
                self._reset_user_password(username)
        elif path == "/api/classify":
            self._classify()
        elif path == "/api/summarize":
            self._summarize()
        elif path == "/api/rules":
            self._save_rules()
        elif path == "/api/wizard":
            self._wizard()
        elif path == "/api/algorithm":
            if self._require_researcher():
                self._save_algorithm()
        elif path == "/api/sensitivity":
            # Auditors and admins can adjust the sensitivity slider for the
            # currently-active algorithm. They do NOT see which algo is active.
            self._save_sensitivity_only()
        elif path == "/api/documents":
            self._upload_document()
        elif path == "/api/events":
            self._log_audit_event()
        elif path == "/api/treatments":
            if self._require_researcher():
                self._create_treatment()
        elif path == "/api/wizard-rule":
            if self._require_admin():
                self._wizard_rule()
        elif path == "/api/seed-mock-data":
            if self._require_researcher():
                try:
                    counts = seed_demo_data()
                    self._json(200, counts)
                except Exception as e:
                    self._json(500, {"error": str(e)})
        elif path == "/api/treatments/end":
            if self._require_researcher():
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    data = json.loads(self.rfile.read(length))
                    db_end_treatment(int(data.get("id")))
                    self._json(200, {"ok": True})
                except Exception as e:
                    self._json(500, {"error": str(e)})
        elif path == "/api/rules/apply-additions":
            # Auditor wizard's "accept proposal" applies the additions to the
            # current ruleset (kept separate from /api/rules to be explicit).
            if self._require_admin():
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    add = json.loads(self.rfile.read(length))
                    cur = load_rules()
                    if add.get("policy_text_addition"):
                        cur["policy_text"] = (cur.get("policy_text", "") + "\n\n" + add["policy_text_addition"]).strip()
                    if isinstance(add.get("new_auto_red_keywords"), list):
                        cur["auto_red_keywords"] = list({*(cur.get("auto_red_keywords") or []), *[str(k).lower() for k in add["new_auto_red_keywords"]]})
                    if isinstance(add.get("new_auto_green_keywords"), list):
                        cur["auto_green_keywords"] = list({*(cur.get("auto_green_keywords") or []), *[str(k).lower() for k in add["new_auto_green_keywords"]]})
                    if isinstance(add.get("new_category_caps"), list):
                        cur["category_caps"] = (cur.get("category_caps") or []) + add["new_category_caps"]
                    saved = save_rules(cur)
                    actor = (session_info(self._bearer_token()) or {}).get("username")
                    log_event("rule_change", actor, "wizard_apply",
                              {"additions": add, "rationale": add.get("rationale", "")})
                    self._json(200, saved)
                except Exception as e:
                    self._json(500, {"error": str(e)})
        else:
            self.send_error(404)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not self._require_admin():
            return
        if path.startswith("/api/users/"):
            username = path[len("/api/users/"):]
            self._delete_user(username)
        else:
            self.send_error(404)

    # ---- auth endpoints ---------------------------------------

    def _login(self):
        ip = self._client_ip()
        locked, retry = is_locked_out(ip)
        if locked:
            return self._json(429, {"error": f"too many failed attempts; try again in {retry}s"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip()
            if not username or not password:
                return self._json(400, {"error": "username and password are required"})
            rec = load_auth()
            user = find_user(rec, username)
            if not user or not _verify_password(password, user["salt"], user["hash"]):
                record_login_failure(ip)
                return self._json(401, {"error": "invalid username or password"})
            reset_failures(ip)
            token, expires_at = issue_session(
                user["username"], user.get("is_admin", False), user.get("is_researcher", False)
            )
            return self._json(200, {
                "token": token,
                "expires_at": int(expires_at),
                "username": user["username"],
                "is_admin": bool(user.get("is_admin")),
                "is_researcher": bool(user.get("is_researcher")),
                "default_password_in_use": user.get("password_changed_at") is None and user.get("is_admin", False),
            })
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _logout(self):
        tok = self._bearer_token()
        if tok:
            revoke_session(tok)
        return self._json(200, {"ok": True})

    def _change_password(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            old = (data.get("old_password") or "").strip()
            new = (data.get("new_password") or "").strip()
            if len(new) < 6:
                return self._json(400, {"error": "new password must be at least 6 characters"})
            tok = self._bearer_token()
            s = session_info(tok)
            if not s:
                return self._json(401, {"error": "not authenticated"})
            rec = load_auth()
            user = find_user(rec, s["username"])
            if not user or not _verify_password(old, user["salt"], user["hash"]):
                return self._json(401, {"error": "current password is incorrect"})
            user["salt"] = secrets.token_hex(16)
            user["hash"] = _hash_password(new, user["salt"])
            user["password_changed_at"] = int(time.time())
            save_auth(rec)
            for t, info in list(_sessions.items()):
                if info.get("username") == user["username"] and t != tok:
                    _sessions.pop(t, None)
            return self._json(200, {"ok": True})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- admin user mgmt --------------------------------------

    def _create_user(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            username = (data.get("username") or "").strip()
            password = (data.get("password") or "").strip()
            is_admin = bool(data.get("is_admin"))
            is_researcher = bool(data.get("is_researcher"))
            if not username or not password:
                return self._json(400, {"error": "username and password are required"})
            if len(username) > 60 or not all(c.isalnum() or c in "._-" for c in username):
                return self._json(400, {"error": "username must be alphanumeric (plus . _ -), max 60 chars"})
            if len(password) < 6:
                return self._json(400, {"error": "password must be at least 6 characters"})
            rec = load_auth()
            if find_user(rec, username):
                return self._json(409, {"error": f"user '{username}' already exists"})
            new_user = _new_user_record(username, password, is_admin, is_researcher)
            new_user["password_changed_at"] = int(time.time())
            rec["users"].append(new_user)
            save_auth(rec)
            return self._json(201, {
                "username": new_user["username"],
                "is_admin": new_user["is_admin"],
                "is_researcher": new_user["is_researcher"],
                "created_at": new_user["created_at"],
            })
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _delete_user(self, username: str):
        try:
            tok = self._bearer_token()
            s = session_info(tok)
            if s and s["username"].lower() == username.lower():
                return self._json(400, {"error": "you cannot delete your own account"})
            rec = load_auth()
            target = find_user(rec, username)
            if not target:
                return self._json(404, {"error": f"user '{username}' not found"})
            if target.get("is_admin") and admin_count(rec) <= 1:
                return self._json(400, {"error": "cannot delete the last admin"})
            rec["users"] = [u for u in rec["users"] if u["username"].lower() != username.lower()]
            save_auth(rec)
            for t, info in list(_sessions.items()):
                if info.get("username", "").lower() == username.lower():
                    _sessions.pop(t, None)
            return self._json(200, {"ok": True})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _reset_user_password(self, username: str):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            new = (data.get("new_password") or "").strip()
            if len(new) < 6:
                return self._json(400, {"error": "new password must be at least 6 characters"})
            rec = load_auth()
            user = find_user(rec, username)
            if not user:
                return self._json(404, {"error": f"user '{username}' not found"})
            user["salt"] = secrets.token_hex(16)
            user["hash"] = _hash_password(new, user["salt"])
            user["password_changed_at"] = int(time.time())
            save_auth(rec)
            for t, info in list(_sessions.items()):
                if info.get("username", "").lower() == username.lower():
                    _sessions.pop(t, None)
            return self._json(200, {"ok": True})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- algorithm config (researcher) -------------------------

    def _save_algorithm(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            saved = save_algorithm_config(data)
            actor = (session_info(self._bearer_token()) or {}).get("username")
            log_event("algorithm_change", actor, saved["active"], saved)
            return self._json(200, saved)
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _save_sensitivity_only(self):
        """Auditor / admin can move the sensitivity slider but not change the
        algorithm itself. Researcher should use /api/algorithm."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            cfg = load_algorithm_config()
            cfg["sensitivity"] = float(data.get("sensitivity", cfg["sensitivity"]))
            saved = save_algorithm_config(cfg)
            actor = (session_info(self._bearer_token()) or {}).get("username")
            log_event("sensitivity_change", actor, saved["active"], {"sensitivity": saved["sensitivity"]})
            return self._json(200, {"sensitivity": saved["sensitivity"]})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- documents ---------------------------------------------

    def _upload_document(self):
        """Multipart-style upload via JSON: {transaction_id, filename, mime_type, content_b64}.
        Keeps things simple - the client base64-encodes the file."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 8 * 1024 * 1024:  # 8 MB hard limit (well under Neon free-tier limits)
                return self._json(413, {"error": "file too large (max 8 MB)"})
            data = json.loads(self.rfile.read(length))
            txn_id = (data.get("transaction_id") or "").strip()
            fname = (data.get("filename") or "upload").strip()[:200]
            mime = (data.get("mime_type") or "application/octet-stream").strip()[:120]
            b64 = data.get("content_b64") or ""
            if not txn_id or not b64:
                return self._json(400, {"error": "transaction_id and content_b64 are required"})
            import base64
            try:
                contents = base64.b64decode(b64, validate=True)
            except Exception:
                return self._json(400, {"error": "content_b64 is not valid base64"})
            if len(contents) > 5 * 1024 * 1024:
                return self._json(413, {"error": "file too large (max 5 MB)"})

            # best-effort PDF text extraction so the LLM can read receipts
            extracted = None
            if mime == "application/pdf" or fname.lower().endswith(".pdf"):
                extracted = extract_text_from_pdf_bytes(contents)

            uploader = (session_info(self._bearer_token()) or {}).get("username", "?")
            doc_id = db_save_document(txn_id, uploader, fname, mime, contents, extracted)
            log_event("document_upload", uploader, txn_id, {
                "doc_id": doc_id, "filename": fname, "mime": mime, "size": len(contents),
                "has_text": extracted is not None,
            })
            return self._json(201, {
                "id": doc_id, "filename": fname, "mime_type": mime,
                "size_bytes": len(contents),
                "extracted_text_preview": (extracted or "")[:300],
            })
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- events ------------------------------------------------

    def _log_audit_event(self):
        """Generic event logger used by the client to persist override decisions etc."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            event_type = (data.get("event_type") or "").strip()
            if not event_type:
                return self._json(400, {"error": "event_type is required"})
            target = data.get("target")
            payload = data.get("payload") or {}
            actor = (session_info(self._bearer_token()) or {}).get("username")
            log_event(event_type, actor, target, payload)
            return self._json(200, {"ok": True})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- treatments (experimental rule deployment) -------------

    def _create_treatment(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            name = (data.get("name") or "").strip()
            rule_payload = data.get("rule_payload") or {}
            target_group = data.get("target_group") or {}
            notes = (data.get("notes") or "").strip()
            if not name:
                return self._json(400, {"error": "treatment name is required"})
            new_id = db_create_treatment(name, rule_payload, target_group, notes)
            actor = (session_info(self._bearer_token()) or {}).get("username")
            log_event("treatment_created", actor, str(new_id), {
                "name": name, "rule_payload": rule_payload, "target_group": target_group,
            })
            return self._json(201, {"id": new_id})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- auditor's rule-creation wizard (LLM-driven) -----------

    def _wizard_rule(self):
        """Two modes:
          * action=ask    : returns the next question for the auditor
          * action=propose: takes the strategy + answers, returns a candidate ruleset
        Strategy text is provided by the auditor at the start."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            strategy = (data.get("strategy") or "").strip()
            history = data.get("history") or []
            mode = (data.get("mode") or "ask").strip()
            current_rules = load_rules()

            if mode == "propose":
                prompt = _rule_wizard_propose_prompt(strategy, history, current_rules)
                client = get_client()
                resp = client.chat.completions.create(
                    model=LLM_MODEL,
                    max_tokens=600,
                    messages=[{"role": "user", "content": prompt}],
                    reasoning_effort="low",
                )
                return self._json(200, {"text": (resp.choices[0].message.content or "").strip()})
            else:
                prompt = _rule_wizard_ask_prompt(strategy, history, current_rules)
                client = get_client()
                resp = client.chat.completions.create(
                    model=LLM_MODEL,
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}],
                    reasoning_effort="low",
                )
                return self._json(200, {"text": (resp.choices[0].message.content or "").strip()})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- rules + LLM endpoints ---------------------------------

    def _save_rules(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                return self._json(400, {"error": "rules payload must be a JSON object"})
            saved = save_rules(data)
            return self._json(200, saved)
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _classify(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            prompt = data.get("prompt", "")
            if not prompt:
                return self._json(400, {"error": "missing prompt"})
            client = get_client()
            resp = client.chat.completions.create(
                model=LLM_MODEL,
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
                reasoning_effort="low",
            )
            text = (resp.choices[0].message.content or "").strip()
            return self._json(200, {"text": text, "model": LLM_MODEL})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _summarize(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            prompt = data.get("prompt", "")
            max_tokens = int(data.get("max_tokens", 600))
            if not prompt:
                return self._json(400, {"error": "missing prompt"})
            client = get_client()
            resp = client.chat.completions.create(
                model=LLM_MODEL,
                max_tokens=max(100, min(max_tokens, 1500)),
                messages=[{"role": "user", "content": prompt}],
                reasoning_effort="low",
            )
            text = (resp.choices[0].message.content or "").strip()
            return self._json(200, {"text": text, "model": LLM_MODEL})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _wizard(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            txn = payload.get("transaction") or {}
            history = payload.get("history") or []
            rules = payload.get("rules") or load_rules()
            max_turns = int(rules.get("wizard_max_turns", 6))
            turns_used = len(history)
            force_conclude = turns_used >= max_turns

            sys_prompt = _wizard_system_prompt(txn, rules, max_turns, turns_used, force_conclude)
            user_prompt = _wizard_user_prompt(history)

            client = get_client()
            resp = client.chat.completions.create(
                model=LLM_MODEL,
                max_tokens=400,
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                reasoning_effort="low",
            )
            text = (resp.choices[0].message.content or "").strip()
            return self._json(200, {"text": text, "model": LLM_MODEL,
                                    "turns_used": turns_used, "force_concluded": force_conclude})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---- low-level helpers ------------------------------------

    def _serve_file(self, path: Path, ctype: str):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[proxy] {self._client_ip()} - {fmt % args}", flush=True)


def _ctype(path: Path) -> str:
    return {
        ".css":  "text/css",
        ".js":   "application/javascript",
        ".html": "text/html; charset=utf-8",
        ".json": "application/json",
    }.get(path.suffix, "application/octet-stream")


class ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


def main() -> None:
    if not ARTIFACT.exists():
        raise SystemExit(f"missing {ARTIFACT}")

    if not os.environ.get("GROQ_API_KEY"):
        raise SystemExit(
            "GROQ_API_KEY env var is not set. Set it in your hosting platform's "
            "environment variables (Render → Settings → Environment)."
        )

    if not DATABASE_URL:
        raise SystemExit(
            "DATABASE_URL env var is not set. Set it to your Postgres connection string\n"
            "(Neon, Supabase, etc.) in the platform's environment variables."
        )

    try:
        import psycopg  # noqa: F401
    except ImportError:
        raise SystemExit(
            "Missing dependency: 'psycopg' is not installed.\n"
            "Run: pip install psycopg[binary]"
        )

    try:
        import openai  # noqa: F401
    except ImportError:
        raise SystemExit("Missing dependency: 'openai' is not installed. Run: pip install openai")

    print("Initialising database schema...", flush=True)
    init_db()
    seeded = seed_default_admin_if_no_users()
    if seeded:
        print(f"  seeded admin: {DEFAULT_ADMIN_USERNAME!r}", flush=True)
        if DEFAULT_ADMIN_PASSWORD == "admin":
            print("  WARNING: default password 'admin' is in use. Change it via the app, "
                  "or set DEFAULT_ADMIN_PASSWORD before first deploy.", flush=True)

    server = ThreadingServer((HOST, PORT), Handler)
    print(f"Serving Expense Anomaly UI on http://{HOST}:{PORT}", flush=True)
    print(f"  model: {LLM_MODEL} (via Groq)", flush=True)
    try:
        rec = load_auth()
        n_users = len(rec.get("users", []))
        n_admins = admin_count(rec)
        if any_default_password_still_used(rec):
            print(f"  auth:  {n_users} user(s), {n_admins} admin(s) - default password still in use!", flush=True)
        else:
            print(f"  auth:  {n_users} user(s), {n_admins} admin(s)", flush=True)
    except Exception:
        pass
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
