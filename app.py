"""lucera-metrics — Metrics API for the client dashboard.

Read-only over the Aiven database. English field names, values and routes.
Protected with JWT (login) — see /auth/login. Sections without data yet
(doctors, medications, scheduling, audit) return empty arrays.
"""

from __future__ import annotations

import hmac
import json
import os
import time
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import jwt
import pymysql
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# ── DB connection (Aiven, read-only) ─────────────────────────────────────────
DB = dict(
    host=os.environ.get("MYSQL_HOST", "127.0.0.1"),
    port=int(os.environ.get("MYSQL_PORT", "3306")),
    user=os.environ.get("MYSQL_USER", "lucera"),
    password=os.environ.get("MYSQL_PASSWORD", "lucera"),
    database=os.environ.get("MYSQL_DB", "lucera"),
    cursorclass=pymysql.cursors.DictCursor,
    charset="utf8mb4",
    autocommit=True,
)
if os.environ.get("MYSQL_SSL", "").lower() in ("1", "true", "yes"):
    import ssl as _ssl

    _ctx = _ssl.create_default_context()
    _ca = os.environ.get("MYSQL_SSL_CA")
    if _ca:
        _ctx.load_verify_locations(_ca)
    else:
        _ctx.check_hostname = False
        _ctx.verify_mode = _ssl.CERT_NONE
    DB["ssl"] = _ctx


def _q(sql: str, args: tuple = ()) -> list[dict]:
    conn = pymysql.connect(**DB)
    try:
        with conn.cursor() as cur:
            if args:
                cur.execute(sql, args)
            else:
                cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


def _clean(v):
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    return v


# ── Auth (JWT + optional API key) ────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "lucera-metrics-dev-secret-CHANGE-ME")
JWT_TTL = int(os.environ.get("JWT_TTL_HOURS", "12")) * 3600
API_KEY = os.environ.get("METRICS_API_KEY", "")


def _load_users() -> dict:
    raw = os.environ.get("METRICS_USERS", "").strip()
    if raw:
        try:
            return {u["email"].lower(): u for u in json.loads(raw)}
        except Exception:  # noqa: BLE001
            pass
    pwd = os.environ.get("METRICS_DEMO_PASSWORD", "Lucera2026!")
    demo = [
        {"email": "admin@lucera.pa", "name": "Admin Técnico", "role": "Admin", "password": pwd},
        {"email": "ventas@lucera.pa", "name": "Ventas", "role": "Sales", "password": pwd},
        {"email": "esanchez@lucera.pa", "name": "Dra. Elena Sánchez", "role": "Doctor", "password": pwd},
    ]
    return {u["email"].lower(): u for u in demo}


USERS = _load_users()


def _check_password(user: dict, password: str) -> bool:
    if "pass_sha256" in user:
        import hashlib

        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), str(user["pass_sha256"]))
    return hmac.compare_digest(str(user.get("password", "")), password)


def require_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> dict:
    if API_KEY and x_api_key and hmac.compare_digest(x_api_key, API_KEY):
        return {"sub": "apikey", "role": "Admin"}
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired. Please log in again.")
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=401, detail="Invalid token.")
    raise HTTPException(status_code=401, detail="Not authenticated (send Bearer <jwt> or X-API-Key).")


class LoginIn(BaseModel):
    email: str
    password: str


app = FastAPI(title="Lucera Metrics API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])


@app.post("/auth/login")
def login(body: LoginIn) -> dict:
    u = USERS.get((body.email or "").lower().strip())
    if u is None or not _check_password(u, body.password or ""):
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    now = int(time.time())
    payload = {"sub": body.email.lower().strip(), "name": u["name"], "role": u["role"], "iat": now, "exp": now + JWT_TTL}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {"email": payload["sub"], "name": u["name"], "role": u["role"]}}


@app.get("/health")
def health():
    try:
        _q("SELECT 1")
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"db: {e}")


# ── Docs at root ─────────────────────────────────────────────────────────────
try:
    _DOCS = (Path(__file__).parent / "docs" / "index.html").read_text(encoding="utf-8")
except Exception:  # noqa: BLE001
    _DOCS = "<h1>Lucera Metrics API</h1><p>See <a href='/docs'>/docs</a>.</p>"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> str:
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Lucera Metrics API</title></head>"
        f"<body>{_DOCS}</body></html>"
    )


# ── Value mappings → English ─────────────────────────────────────────────────
RELATIONSHIP = {"madre": "mother", "padre": "father", "tutor": "guardian", "abuelo": "grandparent", "otro": "guardian"}
GUARDIAN_STATUS = {"active": "active", "inactive": "suspended", "suspended": "suspended", "deleted": "inactive"}
PATIENT_STATUS = {"active": "active", "inactive": "suspended", "suspended": "suspended"}
TRIAGE = {"general": "general", "urgente": "urgent", "emergencia": "emergency"}
PAY_METHOD = {"tilopay": "yappy", "yappy": "yappy", "stripe": "stripe"}
PAY_STATUS = {"confirmed": "confirmed", "pending": "pending", "failed": "failed", "refunded": "refunded"}
MSG_ROLE = {"user": "guardian", "guardian": "guardian", "assistant": "bot", "bot": "bot", "system": "system"}
TRIAGE_COLOR = {"general": "hsl(var(--triage-self))", "urgent": "hsl(var(--triage-priority))", "emergency": "hsl(var(--triage-emergency))"}


def _country(phone: str | None) -> str:
    p = (phone or "").lstrip("+")
    return "Panama" if p.startswith("507") else ("Colombia" if p.startswith("57") else "Panama")


def _age_years(bday) -> int:
    if not bday:
        return 0
    if isinstance(bday, str):
        try:
            bday = date.fromisoformat(bday[:10])
        except ValueError:
            return 0
    t = date.today()
    return t.year - bday.year - ((t.month, t.day) < (bday.month, bday.day))


def _plan(cycle: str | None) -> str:
    return {"annual": "premium_annual", "monthly": "premium_monthly"}.get(cycle, "free")


# ── Guardians ────────────────────────────────────────────────────────────────
@app.get("/api/guardians", dependencies=[Depends(require_auth)])
def guardians() -> list[dict]:
    gs = _q(
        """
        SELECT g.id, g.full_name AS name, g.relationship_type AS rel, g.city, g.province,
               u.phone_number AS phone, u.email, u.status AS ustatus, u.created_at,
               (SELECT p.billing_cycle FROM payments p WHERE p.user_id=u.id AND p.status='confirmed'
                 ORDER BY p.confirmed_at DESC LIMIT 1) AS cycle
        FROM guardians g JOIN users u ON u.id=g.user_id ORDER BY g.full_name
        """
    )
    deps = _q(
        """
        SELECT gd.guardian_id, d.id, d.full_name AS name, d.birthday, d.blood_type, d.weight_kg,
               d.known_conditions, d.allergies
        FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id
        """
    )
    by_g: dict = {}
    for d in deps:
        by_g.setdefault(d["guardian_id"], []).append({
            "id": d["id"], "name": d["name"], "birthDate": _clean(d["birthday"]),
            "bloodType": d["blood_type"] or None,
            "weightKg": float(d["weight_kg"]) if d["weight_kg"] is not None else None,
            "conditions": [d["known_conditions"]] if d["known_conditions"] else [],
            "allergies": [d["allergies"]] if d["allergies"] else [],
        })
    return [{
        "id": g["id"], "phone": g["phone"], "email": g["email"], "name": g["name"],
        "relationship": RELATIONSHIP.get(g["rel"], "guardian"),
        "country": _country(g["phone"]), "city": g["city"] or g["province"] or "",
        "status": GUARDIAN_STATUS.get(g["ustatus"], "active"), "plan": _plan(g["cycle"]),
        "registeredAt": _clean(g["created_at"]), "children": by_g.get(g["id"], []),
    } for g in gs]


# ── Patients ─────────────────────────────────────────────────────────────────
@app.get("/api/patients", dependencies=[Depends(require_auth)])
def patients() -> list[dict]:
    rows = _q(
        """
        SELECT d.id, d.full_name AS name, d.birthday, d.css_number AS national_id,
               g.full_name AS guardian, u.phone_number AS phone, u.status AS ustatus,
               (SELECT MAX(cs.opened_at) FROM chat_sessions cs WHERE cs.dependent_id=d.id) AS last
        FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id
        JOIN guardians g ON g.id=gd.guardian_id JOIN users u ON u.id=g.user_id ORDER BY d.full_name
        """
    )
    return [{
        "id": r["id"], "name": r["name"], "nationalId": r["national_id"] or "",
        "age": _age_years(r["birthday"]), "guardian": r["guardian"], "phone": r["phone"],
        "status": PATIENT_STATUS.get(r["ustatus"], "pending"),
        "lastConsultation": _clean(r["last"]) if r["last"] else "",
    } for r in rows]


# ── Chats ────────────────────────────────────────────────────────────────────
@app.get("/api/chats", dependencies=[Depends(require_auth)])
def chats() -> list[dict]:
    ses = _q(
        """
        SELECT cs.id, g.full_name AS guardian, d.full_name AS patient, u.phone_number AS phone,
               cl.name AS triage, cs.appointment_type, cs.summary AS ai_summary,
               cs.feedback_score AS rating, cs.status, cs.fsm_state, cs.opened_at AS started_at,
               cs.closed_at AS closed_at,
               (SELECT content FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
               (SELECT created_at FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS time
        FROM chat_sessions cs JOIN guardians g ON g.id=cs.guardian_id JOIN users u ON u.id=g.user_id
        LEFT JOIN dependents d ON d.id=cs.dependent_id
        LEFT JOIN classification cl ON cl.id=cs.classification_id
        ORDER BY cs.opened_at DESC
        """
    )
    msgs = _q(
        """
        SELECT m.session_id, m.sender_role, m.content, m.created_at, m.content_type,
               GROUP_CONCAT(mf.flag_type) AS flags
        FROM messages m LEFT JOIN message_flags mf ON mf.message_id=m.id
        GROUP BY m.id, m.session_id, m.sender_role, m.content, m.created_at, m.content_type
        ORDER BY m.created_at ASC
        """
    )
    by_s: dict = {}
    for m in msgs:
        by_s.setdefault(m["session_id"], []).append({
            "role": MSG_ROLE.get(m["sender_role"], "system"), "text": m["content"],
            "time": _clean(m["created_at"]), "type": (m["content_type"] or "text"),
            "alerts": (m["flags"].split(",") if m["flags"] else []),
        })

    def _status(s):
        if s["status"] == "closed":
            return "closed"
        if s["fsm_state"] == "awaiting_user":
            return "waiting"
        return "active"

    return [{
        "id": s["id"], "guardian": s["guardian"], "patient": s["patient"] or "", "phone": s["phone"],
        "triage": TRIAGE.get(s["triage"], "general"),
        "attentionType": "in_person" if (s["appointment_type"] or "").lower().startswith("pres") else "virtual",
        "aiSummary": s["ai_summary"] or None,
        "rating": int(s["rating"]) if s["rating"] is not None else None,
        "lastMessage": (s["last_message"] or "")[:200], "time": _clean(s["time"]) if s["time"] else "",
        "startedAt": _clean(s["started_at"]) if s["started_at"] else "",
        "closedAt": _clean(s["closed_at"]) if s["closed_at"] else None,
        "messages": by_s.get(s["id"], []), "status": _status(s),
    } for s in ses]


# ── Payments ─────────────────────────────────────────────────────────────────
@app.get("/api/payments", dependencies=[Depends(require_auth)])
def payments() -> list[dict]:
    rows = _q(
        """
        SELECT p.id, p.provider_txn_id, g.full_name AS guardian, p.amount_usd AS amount,
               p.provider, p.billing_cycle, p.status, p.created_at, p.confirmed_at
        FROM payments p JOIN users u ON u.id=p.user_id LEFT JOIN guardians g ON g.user_id=u.id
        ORDER BY p.created_at DESC
        """
    )
    return [{
        "id": r["provider_txn_id"] or r["id"], "guardian": r["guardian"] or "",
        "amount": float(r["amount"]) if r["amount"] is not None else 0,
        "method": PAY_METHOD.get(r["provider"], "yappy"), "plan": _plan(r["billing_cycle"]),
        "status": PAY_STATUS.get(r["status"], "pending"),
        "date": _clean(r["confirmed_at"] or r["created_at"]),
        "providerResponse": r["status"], "paymentType": "credit",
    } for r in rows]


# ── Health centers ───────────────────────────────────────────────────────────
@app.get("/api/centers", dependencies=[Depends(require_auth)])
def centers() -> list[dict]:
    rows = _q(
        "SELECT id, name, city, address, phone, recommended FROM hospitals "
        "WHERE active=1 OR active IS NULL ORDER BY name"
    )
    out = []
    for r in rows:
        nm = (r["name"] or "").lower()
        typ = "Clinic" if ("clínic" in nm or "clinic" in nm) else ("Emergency" if "urgenc" in nm else "Hospital")
        out.append({
            "id": r["id"], "name": r["name"], "type": typ, "city": r["city"] or "",
            "address": r["address"] or "", "phone": r["phone"] or "", "hours": "24/7",
            "recommended": bool(r["recommended"]),
        })
    return out


# ── Catalogs ─────────────────────────────────────────────────────────────────
@app.get("/api/insurances", dependencies=[Depends(require_auth)])
def insurances() -> list[dict]:
    return [{"id": r["id"], "name": r["name"]} for r in _q("SELECT id, name FROM insurance_companies ORDER BY name")]


@app.get("/api/specialties", dependencies=[Depends(require_auth)])
def specialties() -> list[str]:
    return [r["name"] for r in _q("SELECT name FROM specialties ORDER BY name")]


# ── Statistics ───────────────────────────────────────────────────────────────
@app.get("/api/stats/kpis", dependencies=[Depends(require_auth)])
def kpis() -> dict:
    active = _q("SELECT COUNT(*) c FROM users WHERE status='active'")[0]["c"]
    children = _q("SELECT COUNT(*) c FROM dependents")[0]["c"]
    sm = _q("SELECT COUNT(*) c FROM chat_sessions WHERE opened_at >= DATE_FORMAT(NOW(),'%Y-%m-01')")[0]["c"]
    paid = _q("SELECT COUNT(DISTINCT user_id) c FROM payments WHERE status='confirmed'")[0]["c"]
    total = _q("SELECT COUNT(*) c FROM users")[0]["c"] or 1
    csat = _q("SELECT AVG(feedback_score) a FROM chat_sessions")[0]["a"]
    emg = _q("SELECT COUNT(*) c FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id WHERE cl.name='emergencia'")[0]["c"]
    ref = _q("SELECT COUNT(*) c FROM chat_sessions WHERE hospital_id IS NOT NULL OR appointment_type='presencial'")[0]["c"]
    rev = _q("SELECT COALESCE(SUM(amount_usd),0) s FROM payments WHERE status='confirmed' AND confirmed_at >= DATE_FORMAT(NOW(),'%Y-%m-01')")[0]["s"]
    return {
        "activeGuardians": active, "registeredChildren": children, "sessionsThisMonth": sm,
        "premiumConversion": round(paid / total * 100, 1),
        "csat": round(float(csat) / 5 * 100) if csat else 0,
        "emergenciesDetected": emg, "inPersonReferrals": ref, "revenueThisMonth": float(rev),
    }


_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


@app.get("/api/stats/sessions-per-month", dependencies=[Depends(require_auth)])
def sessions_per_month() -> list[dict]:
    rows = _q("SELECT YEAR(opened_at) y, MONTH(opened_at) m, COUNT(*) sessions FROM chat_sessions "
              "WHERE opened_at IS NOT NULL GROUP BY YEAR(opened_at), MONTH(opened_at) ORDER BY y, m")
    prem = _q("SELECT YEAR(confirmed_at) y, MONTH(confirmed_at) m, COUNT(*) premium FROM payments "
              "WHERE status='confirmed' AND confirmed_at IS NOT NULL GROUP BY YEAR(confirmed_at), MONTH(confirmed_at)")
    pmap = {(p["y"], p["m"]): p["premium"] for p in prem}
    return [{"month": _MONTHS[r["m"] - 1], "sessions": r["sessions"], "premium": pmap.get((r["y"], r["m"]), 0)} for r in rows]


@app.get("/api/stats/triage", dependencies=[Depends(require_auth)])
def stats_triage() -> list[dict]:
    rows = _q("SELECT cl.name, COUNT(*) value FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id GROUP BY cl.name")
    order = {"general": 0, "urgente": 1, "emergencia": 2}
    rows.sort(key=lambda r: order.get(r["name"], 9))
    return [{"level": TRIAGE.get(r["name"], r["name"]).capitalize(), "value": r["value"],
             "color": TRIAGE_COLOR.get(TRIAGE.get(r["name"], ""), "")} for r in rows]


@app.get("/api/stats/plans", dependencies=[Depends(require_auth)])
def stats_plans() -> list[dict]:
    rows = _q("SELECT COALESCE((SELECT p.billing_cycle FROM payments p WHERE p.user_id=u.id AND p.status='confirmed' "
              "ORDER BY p.confirmed_at DESC LIMIT 1),'free') AS cycle, COUNT(*) c FROM users u GROUP BY cycle")
    colors = {"free": "hsl(var(--triage-self))", "premium_monthly": "hsl(var(--accent))", "premium_annual": "hsl(var(--primary))"}
    agg: dict = {}
    for r in rows:
        agg[_plan(r["cycle"])] = agg.get(_plan(r["cycle"]), 0) + r["c"]
    return [{"plan": k, "users": v, "color": colors.get(k, "")} for k, v in agg.items()]


@app.get("/api/stats/attention-type", dependencies=[Depends(require_auth)])
def stats_attention_type() -> list[dict]:
    pres = _q("SELECT COUNT(*) c FROM chat_sessions WHERE hospital_id IS NOT NULL OR appointment_type='presencial'")[0]["c"]
    tot = _q("SELECT COUNT(*) c FROM chat_sessions")[0]["c"]
    return [{"type": "virtual", "value": tot - pres}, {"type": "in_person", "value": pres}]


@app.get("/api/stats/csat", dependencies=[Depends(require_auth)])
def stats_csat() -> list[dict]:
    rows = _q("SELECT YEARWEEK(closed_at) yw, ROUND(AVG(feedback_score)/5*100) csat FROM chat_sessions "
              "WHERE feedback_score IS NOT NULL AND closed_at IS NOT NULL GROUP BY YEARWEEK(closed_at) ORDER BY yw")
    return [{"week": f"W{i + 1}", "csat": int(r["csat"])} for i, r in enumerate(rows)]


# ── Future sections (empty until the product has the data) ───────────────────
@app.get("/api/doctors", dependencies=[Depends(require_auth)])
def doctors() -> list[dict]:
    return []


@app.get("/api/specialists", dependencies=[Depends(require_auth)])
def specialists() -> list[dict]:
    return []


@app.get("/api/medications", dependencies=[Depends(require_auth)])
def medications() -> list[dict]:
    return []


@app.get("/api/availability", dependencies=[Depends(require_auth)])
def availability() -> list[dict]:
    return []


@app.get("/api/appointments", dependencies=[Depends(require_auth)])
def appointments() -> list[dict]:
    return []


@app.get("/api/logs", dependencies=[Depends(require_auth)])
def logs() -> list[dict]:
    return []
