"""lucera-metrics — backend for the client dashboard.

Read + write over the Aiven database. English fields/routes. JWT auth with
refresh tokens. Paginated lists, CRUD for guardians/patients, usage (consumos)
endpoints, in-memory cache for stats/usage. Empty sections return paginated [].
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import jwt
import pymysql
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# ── DB ───────────────────────────────────────────────────────────────────────
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


# ── Health del bot de WhatsApp (proxy al /ready del servicio del bot) ─────────
BOT_HEALTH_URL = os.environ.get(
    "BOT_HEALTH_URL", "https://lucera-botdev-nz76w2xbra-uc.a.run.app/ready"
)
BOT_HEALTH_TIMEOUT = float(os.environ.get("BOT_HEALTH_TIMEOUT", "8"))


def _q(sql: str, args: tuple = ()) -> list[dict]:
    conn = pymysql.connect(**DB)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args) if args else cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


def _exec(sql: str, args: tuple = ()) -> int:
    conn = pymysql.connect(**DB)
    try:
        with conn.cursor() as cur:
            return cur.execute(sql, args) if args else cur.execute(sql)
    finally:
        conn.close()


def _tx(statements: list[tuple]) -> None:
    conn = pymysql.connect(**{**DB, "autocommit": False})
    try:
        with conn.cursor() as cur:
            for sql, args in statements:
                cur.execute(sql, args) if args else cur.execute(sql)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _guard_integrity(fn):
    """Run a write, translating DB constraint errors into 409s."""
    try:
        return fn()
    except pymysql.err.IntegrityError as e:
        msg = e.args[1] if len(e.args) > 1 else str(e)
        if "foreign key" in msg.lower():
            raise HTTPException(status_code=409, detail="Cannot delete: still referenced by other records.")
        raise HTTPException(status_code=409, detail="Duplicate or invalid value (unique/constraint).")


def _clean(v):
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    return v


# ── In-memory cache (per instance) ───────────────────────────────────────────
_CACHE: dict = {}


def _cached(key: str, ttl: int, fn):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _CACHE[key] = (now, val)
    return val


# ── Auth (access + refresh JWT) ──────────────────────────────────────────────
JWT_SECRET = os.environ.get("JWT_SECRET", "lucera-metrics-dev-secret-CHANGE-ME")
ACCESS_TTL = int(os.environ.get("ACCESS_TTL_HOURS", "2")) * 3600
REFRESH_TTL = int(os.environ.get("REFRESH_TTL_DAYS", "30")) * 86400
API_KEY = os.environ.get("METRICS_API_KEY", "")

# Registro del portal: el bot manda un link firmado al form del dashboard donde el
# acudiente fija SU contraseña. Secreto COMPARTIDO con el bot para que pueda emitir el token.
PORTAL_TOKEN_SECRET = os.environ.get("PORTAL_TOKEN_SECRET", JWT_SECRET)
PORTAL_REGISTER_URL = os.environ.get("PORTAL_REGISTER_URL", "")  # URL del form de Mauro
REGISTER_TTL = int(os.environ.get("REGISTER_TTL_HOURS", "72")) * 3600


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
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), str(user["pass_sha256"]))
    return hmac.compare_digest(str(user.get("password", "")), password)


def _make_token(sub: str, name: str, role: str, typ: str, ttl: int, **extra) -> str:
    now = int(time.time())
    claims = {"sub": sub, "name": name, "role": role, "typ": typ, "iat": now, "exp": now + ttl}
    claims.update({k: v for k, v in extra.items() if v is not None})
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


# ── Password hashing (PBKDF2-HMAC-SHA256, sin dependencias externas) ──────────
_PBKDF2_ITER = 200_000


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITER)
    return f"pbkdf2_sha256${_PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def _digits(s: str | None) -> str:
    return re.sub(r"\D", "", s or "")


def _make_register_token(gid: str) -> str:
    """Token firmado para el link de registro del portal (identifica al acudiente)."""
    now = int(time.time())
    return jwt.encode(
        {"sub": gid, "typ": "register", "iat": now, "exp": now + REGISTER_TTL},
        PORTAL_TOKEN_SECRET, algorithm="HS256",
    )


def _verify_register_token(token: str) -> str:
    """Valida el token del link de registro y devuelve el id del acudiente (gid)."""
    try:
        c = jwt.decode(token, PORTAL_TOKEN_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=410, detail="Registration link expired.")
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=400, detail="Invalid registration link.")
    if c.get("typ") != "register" or not c.get("sub"):
        raise HTTPException(status_code=400, detail="Invalid registration token.")
    return c["sub"]


def require_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Auth de OPERADORES del tablero. Rechaza tokens del portal del acudiente."""
    if API_KEY and x_api_key and hmac.compare_digest(x_api_key, API_KEY):
        return {"sub": "apikey", "role": "Admin"}
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired. Use /auth/refresh.")
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=401, detail="Invalid token.")
        if claims.get("typ") == "refresh":
            raise HTTPException(status_code=401, detail="Refresh token cannot be used for API calls.")
        if claims.get("scope") == "portal":
            raise HTTPException(status_code=403, detail="Guardian portal token cannot access admin endpoints.")
        return claims
    raise HTTPException(status_code=401, detail="Not authenticated (send Bearer <access_token> or X-API-Key).")


def require_guardian(authorization: str | None = Header(default=None)) -> str:
    """Auth del PORTAL DEL ACUDIENTE. Devuelve el id del acudiente (gid) del token."""
    if not (authorization and authorization.lower().startswith("bearer ")):
        raise HTTPException(status_code=401, detail="Not authenticated (guardian Bearer token required).")
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired. Use /auth/refresh.")
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Invalid token.")
    if claims.get("typ") == "refresh" or claims.get("scope") != "portal" or not claims.get("gid"):
        raise HTTPException(status_code=403, detail="Not a guardian portal token.")
    return claims["gid"]


class LoginIn(BaseModel):
    email: str
    password: str


class GuardianLoginIn(BaseModel):
    phone: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


app = FastAPI(title="Lucera Metrics API", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.post("/auth/login")
def login(body: LoginIn) -> dict:
    u = USERS.get((body.email or "").lower().strip())
    if u is None or not _check_password(u, body.password or ""):
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    sub = body.email.lower().strip()
    return {
        "access_token": _make_token(sub, u["name"], u["role"], "access", ACCESS_TTL),
        "refresh_token": _make_token(sub, u["name"], u["role"], "refresh", REFRESH_TTL),
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "user": {"email": sub, "name": u["name"], "role": u["role"]},
    }


@app.post("/auth/guardian/login")
def guardian_login(body: GuardianLoginIn) -> dict:
    """Portal del acudiente: login con TELÉFONO + contraseña. Devuelve un token con
    scope='portal' que SOLO puede leer los datos del propio acudiente (no PII de otros)."""
    phone = _digits(body.phone)
    rows = _q(
        """SELECT g.id AS gid, g.full_name AS name, u.password_hash AS ph, u.status AS ustatus
           FROM guardians g JOIN users u ON u.id=g.user_id
           WHERE u.phone_number=%s AND u.deleted_at IS NULL""",
        (phone,),
    )
    if not rows or not _verify_password(body.password or "", rows[0]["ph"]):
        raise HTTPException(status_code=401, detail="Wrong phone or password.")
    if rows[0]["ustatus"] != "active":
        raise HTTPException(status_code=403, detail="Account is not active.")
    g = rows[0]
    return {
        "access_token": _make_token(g["gid"], g["name"], "Guardian", "access", ACCESS_TTL, scope="portal", gid=g["gid"]),
        "refresh_token": _make_token(g["gid"], g["name"], "Guardian", "refresh", REFRESH_TTL, scope="portal", gid=g["gid"]),
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "guardian": {"id": g["gid"], "name": g["name"]},
    }


@app.post("/auth/refresh")
def refresh(body: RefreshIn) -> dict:
    try:
        c = jwt.decode(body.refresh_token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired. Log in again.")
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=401, detail="Invalid refresh token.")
    if c.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token.")
    return {
        "access_token": _make_token(
            c["sub"], c.get("name", ""), c.get("role", ""), "access", ACCESS_TTL,
            scope=c.get("scope"), gid=c.get("gid"),   # preserva el scope del portal si aplica
        ),
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
    }


@app.get("/health")
def health():
    try:
        _q("SELECT 1")
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"db: {e}")


@app.get("/api/bot-status", dependencies=[Depends(require_auth)])
def bot_status():
    """Estado del bot de WhatsApp para el tablero: hace ping al /ready del bot.

    Devuelve SIEMPRE 200 (para que el front lo parsee sin ambigüedad):
      bot='up'   → el proceso del bot respondió; `ready` y `checks` reflejan sus dependencias
                   (mysql/redis/rag). `ready=false` = el bot está arriba pero algo falla.
      bot='down' → el bot no respondió (caído, cold start > timeout, o red).
    """
    import urllib.request

    t0 = time.time()
    checked_at = datetime.utcnow().isoformat() + "Z"
    try:
        req = urllib.request.Request(BOT_HEALTH_URL, headers={"User-Agent": "lucera-metrics/bot-status"})
        with urllib.request.urlopen(req, timeout=BOT_HEALTH_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "replace")
        data = json.loads(raw) if raw else {}
        if not isinstance(data, dict):
            data = {}
        return {
            "bot": "up",
            "ready": bool(data.get("ready", False)),
            "checks": data.get("checks", {}),
            "latency_ms": int((time.time() - t0) * 1000),
            "checked_at": checked_at,
            "url": BOT_HEALTH_URL,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "bot": "down",
            "ready": False,
            "checks": {},
            "latency_ms": int((time.time() - t0) * 1000),
            "checked_at": checked_at,
            "url": BOT_HEALTH_URL,
            "error": str(e)[:200],
        }


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


# ── Value maps ───────────────────────────────────────────────────────────────
REL_OUT = {"madre": "mother", "padre": "father", "tutor": "guardian", "abuelo": "grandparent", "otro": "guardian"}
REL_IN = {"mother": "madre", "father": "padre", "guardian": "tutor", "grandparent": "abuelo"}
GSTATUS_OUT = {"active": "active", "inactive": "suspended", "suspended": "suspended", "deleted": "inactive"}
STATUS_IN = {"active": "active", "suspended": "suspended", "inactive": "inactive"}
PSTATUS_OUT = {"active": "active", "inactive": "suspended", "suspended": "suspended"}
TRIAGE = {"general": "general", "urgente": "urgent", "emergencia": "emergency"}
PAY_METHOD = {"tilopay": "yappy", "yappy": "yappy", "stripe": "stripe"}
PAY_STATUS = {"confirmed": "confirmed", "pending": "pending", "failed": "failed", "refunded": "refunded"}
MSG_ROLE = {"user": "guardian", "guardian": "guardian", "assistant": "bot", "bot": "bot", "system": "system"}
TRIAGE_COLOR = {"general": "hsl(var(--triage-self))", "urgent": "hsl(var(--triage-priority))", "emergency": "hsl(var(--triage-emergency))"}
BLOOD_OUT = {"a_pos": "A+", "a_neg": "A-", "b_pos": "B+", "b_neg": "B-", "ab_pos": "AB+", "ab_neg": "AB-", "o_pos": "O+", "o_neg": "O-"}
BLOOD_IN = {v: k for k, v in BLOOD_OUT.items()}


def _country(phone: str | None) -> str:
    p = (phone or "").lstrip("+")
    return "Panama" if p.startswith("507") else ("Colombia" if p.startswith("57") else "Panama")


def _age(bday) -> int:
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


def _split(txt: str | None) -> list[str]:
    return [s.strip() for s in txt.split(";") if s.strip()] if txt else []


def _child(d: dict) -> dict:
    return {
        "id": d["id"], "name": d["name"], "birthDate": _clean(d["birthday"]),
        "bloodType": BLOOD_OUT.get(d.get("blood_type"), None),
        "weightKg": float(d["weight_kg"]) if d.get("weight_kg") is not None else None,
        "conditions": _split(d.get("known_conditions")), "allergies": _split(d.get("allergies")),
        "insurance": (
            {"id": d["ins_id"], "name": d["ins_name"], "policyNumber": d.get("policy") or None}
            if d.get("ins_id") else None
        ),
    }


# ── Pagination ───────────────────────────────────────────────────────────────
def _pag(page: int, page_limit: int):
    page = max(1, page)
    page_limit = min(200, max(1, page_limit))
    return page, page_limit, (page - 1) * page_limit


def _envelope(items, page, page_limit, total):
    return {"items": items, "page": page, "page_limit": page_limit, "total": total,
            "total_pages": (total + page_limit - 1) // page_limit if page_limit else 1}


# ── Guardians (CRUD) ─────────────────────────────────────────────────────────
def _children_for(gids: list[str]) -> dict:
    if not gids:
        return {}
    ph = ",".join(["%s"] * len(gids))
    deps = _q(
        f"""SELECT gd.guardian_id, d.id, d.full_name AS name, d.birthday, d.blood_type, d.weight_kg,
               d.known_conditions, d.allergies, d.insurance_company_id AS ins_id, ic.name AS ins_name,
               d.policy_number AS policy
            FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id
            LEFT JOIN insurance_companies ic ON ic.id=d.insurance_company_id
            WHERE gd.guardian_id IN ({ph})""",
        tuple(gids),
    )
    out: dict = {}
    for d in deps:
        out.setdefault(d["guardian_id"], []).append(_child(d))
    return out


def _guardian_row(g: dict, kids: list[dict]) -> dict:
    insurance = (
        {"id": g["ins_id"], "name": g["ins_name"], "policyNumber": g.get("policy") or None}
        if g.get("ins_id") else None
    )
    return {
        "id": g["id"], "phone": g["phone"], "email": g["email"], "name": g["name"],
        "relationship": REL_OUT.get(g["rel"], "guardian"),
        "country": g.get("country") or _country(g["phone"]),   # nativo; fallback al prefijo del teléfono
        "city": g["city"] or g["province"] or "", "status": GSTATUS_OUT.get(g["ustatus"], "active"),
        "plan": _plan(g["cycle"]), "insurance": insurance, "registeredAt": _clean(g["created_at"]),
        "portalEnabled": bool(g.get("portal_enabled")),   # ¿ya fijó contraseña del portal?
        "children": kids,
    }


_G_SELECT = """SELECT g.id, g.full_name AS name, g.relationship_type AS rel, g.country, g.city, g.province,
    g.insurance_company_id AS ins_id, ic.name AS ins_name, g.policy_number AS policy,
    u.phone_number AS phone, u.email, u.status AS ustatus, u.created_at,
    LEFT(u.password_hash, 6) = 'pbkdf2' AS portal_enabled,
    (SELECT p.billing_cycle FROM payments p WHERE p.user_id=u.id AND p.status='confirmed'
      ORDER BY p.confirmed_at DESC LIMIT 1) AS cycle
    FROM guardians g JOIN users u ON u.id=g.user_id
    LEFT JOIN insurance_companies ic ON ic.id=g.insurance_company_id"""


@app.get("/api/guardians", dependencies=[Depends(require_auth)])
def guardians(page: int = 1, page_limit: int = 20, q: str | None = Query(default=None)):
    page, page_limit, off = _pag(page, page_limit)
    where = "WHERE u.deleted_at IS NULL"
    args: list = []
    if q:
        where += " AND (g.full_name LIKE %s OR u.phone_number LIKE %s OR u.email LIKE %s)"
        args += [f"%{q}%"] * 3
    total = _q(f"SELECT COUNT(*) c FROM guardians g JOIN users u ON u.id=g.user_id {where}", tuple(args))[0]["c"]
    gs = _q(f"{_G_SELECT} {where} ORDER BY g.full_name LIMIT %s OFFSET %s", tuple(args + [page_limit, off]))
    kids = _children_for([g["id"] for g in gs])
    return _envelope([_guardian_row(g, kids.get(g["id"], [])) for g in gs], page, page_limit, total)


def _one_guardian(gid: str) -> dict:
    gs = _q(f"{_G_SELECT} WHERE g.id=%s", (gid,))
    if not gs:
        raise HTTPException(status_code=404, detail="Guardian not found.")
    kids = _children_for([gid])
    return _guardian_row(gs[0], kids.get(gid, []))


# El "plan" no es una columna: se deriva del último pago confirmado (billing_cycle).
# Fijarlo desde el panel = registrar/anular un pago confirmado del acudiente.
def _current_plan(uid: str) -> str:
    r = _q("SELECT billing_cycle FROM payments WHERE user_id=%s AND status='confirmed' "
           "ORDER BY confirmed_at DESC LIMIT 1", (uid,))
    return _plan(r[0]["billing_cycle"]) if r else "free"


def _apply_plan(uid: str, plan: str | None) -> None:
    if plan is None:
        return
    plan = plan.lower()
    if plan not in ("free", "premium_monthly", "premium_annual"):
        raise HTTPException(status_code=422, detail="plan must be free|premium_monthly|premium_annual.")
    if _current_plan(uid) == plan:
        return  # sin cambios
    # anula cualquier pago confirmado previo (→ vuelve a free)
    _exec("UPDATE payments SET status='refunded' WHERE user_id=%s AND status='confirmed'", (uid,))
    if plan == "free":
        return
    cycle = "annual" if plan == "premium_annual" else "monthly"
    prem = _q("SELECT id, price_monthly_usd, price_annual_usd FROM subscription_plans "
              "WHERE active=1 AND price_monthly_usd>0 ORDER BY price_monthly_usd LIMIT 1")
    if not prem:
        raise HTTPException(status_code=409, detail="No active premium plan to assign.")
    amount = prem[0]["price_annual_usd"] if cycle == "annual" else prem[0]["price_monthly_usd"]
    _exec("""INSERT INTO payments (id, user_id, plan_id, billing_cycle, provider, amount_usd, status, created_at, confirmed_at)
             VALUES (%s,%s,%s,%s,'tilopay',%s,'confirmed',NOW(),NOW())""",
          (str(uuid.uuid4()), uid, prem[0]["id"], cycle, amount))


class GuardianCreate(BaseModel):
    name: str
    phone: str
    email: str
    relationship: str | None = None
    country: str | None = None       # país editable (guardians.country)
    city: str | None = None
    province: str | None = None
    address: str | None = None
    status: str | None = None        # active|suspended|inactive (def. active)
    plan: str | None = None          # free|premium_monthly|premium_annual
    insuranceId: int | None = None   # seguro del acudiente (guardians.insurance_company_id)
    policyNumber: str | None = None


@app.post("/api/guardians", dependencies=[Depends(require_auth)], status_code=201)
def guardian_create(body: GuardianCreate):
    rel = REL_IN.get((body.relationship or "guardian").lower(), "tutor")
    status = STATUS_IN.get((body.status or "active").lower(), "active")
    phone = body.phone.strip().lstrip("+")
    uid, gid = str(uuid.uuid4()), str(uuid.uuid4())
    _guard_integrity(lambda: _tx([
        ("""INSERT INTO users (id, email, phone_number, password_hash, role, status, is_active, created_at, updated_at)
             VALUES (%s,%s,%s,%s,'guardian',%s,%s,NOW(),NOW())""",
         (uid, body.email.strip().lower(), phone, "!dashboard-created", status, 0 if status != "active" else 1)),
        ("""INSERT INTO guardians (id, user_id, full_name, relationship_type, address, country, city, province,
             insurance_company_id, policy_number, created_at)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
         (gid, uid, body.name.strip(), rel, body.address, body.country, body.city, body.province,
          body.insuranceId, body.policyNumber)),
    ]))
    _apply_plan(uid, body.plan)
    return _one_guardian(gid)


@app.get("/api/guardians/{gid}", dependencies=[Depends(require_auth)])
def guardian_get(gid: str):
    return _one_guardian(gid)


class GuardianUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    country: str | None = None       # país editable (guardians.country)
    city: str | None = None
    province: str | None = None
    relationship: str | None = None
    status: str | None = None
    plan: str | None = None          # free|premium_monthly|premium_annual
    insuranceId: int | None = None   # seguro del acudiente (guardians.insurance_company_id)
    policyNumber: str | None = None


@app.patch("/api/guardians/{gid}", dependencies=[Depends(require_auth)])
def guardian_update(gid: str, body: GuardianUpdate):
    g = _q("SELECT g.id, g.user_id FROM guardians g WHERE g.id=%s", (gid,))
    if not g:
        raise HTTPException(status_code=404, detail="Guardian not found.")
    uid = g[0]["user_id"]
    gsets, gargs = [], []
    if body.name is not None:
        gsets.append("full_name=%s"); gargs.append(body.name.strip())
    if body.country is not None:
        gsets.append("country=%s"); gargs.append(body.country.strip() or None)
    if body.city is not None:
        gsets.append("city=%s"); gargs.append(body.city.strip())
    if body.province is not None:
        gsets.append("province=%s"); gargs.append(body.province.strip())
    if body.relationship is not None:
        rel = REL_IN.get(body.relationship.lower())
        if not rel:
            raise HTTPException(status_code=422, detail="relationship must be mother|father|guardian|grandparent.")
        gsets.append("relationship_type=%s"); gargs.append(rel)
    if body.insuranceId is not None:
        gsets.append("insurance_company_id=%s"); gargs.append(body.insuranceId or None)
    if body.policyNumber is not None:
        gsets.append("policy_number=%s"); gargs.append(body.policyNumber or None)
    if gsets:
        _guard_integrity(lambda: _exec(f"UPDATE guardians SET {', '.join(gsets)} WHERE id=%s", tuple(gargs + [gid])))
    usets, uargs = [], []
    if body.email is not None:
        usets.append("email=%s"); uargs.append(body.email.strip())
    if body.status is not None:
        st = STATUS_IN.get(body.status.lower())
        if not st:
            raise HTTPException(status_code=422, detail="status must be active|suspended|inactive.")
        usets.append("status=%s"); uargs.append(st)
        usets.append("is_active=%s"); uargs.append(1 if st == "active" else 0)
    if usets:
        _exec(f"UPDATE users SET {', '.join(usets)}, updated_at=NOW() WHERE id=%s", tuple(uargs + [uid]))
    _apply_plan(uid, body.plan)
    return _one_guardian(gid)


@app.delete("/api/guardians/{gid}", dependencies=[Depends(require_auth)])
def guardian_delete(gid: str):
    g = _q("SELECT user_id FROM guardians g WHERE g.id=%s", (gid,))
    if not g:
        raise HTTPException(status_code=404, detail="Guardian not found.")
    _exec("UPDATE users SET status='inactive', is_active=0, deleted_at=NOW(), updated_at=NOW() WHERE id=%s",
          (g[0]["user_id"],))
    return {"deleted": True, "id": gid}


class PortalPassword(BaseModel):
    password: str


@app.post("/api/guardians/{gid}/portal-password", dependencies=[Depends(require_auth)])
def guardian_set_portal_password(gid: str, body: PortalPassword):
    """Admin: fija/actualiza la contraseña del portal del acudiente (habilita su login)."""
    g = _q("SELECT user_id FROM guardians WHERE id=%s", (gid,))
    if not g:
        raise HTTPException(status_code=404, detail="Guardian not found.")
    if len(body.password or "") < 6:
        raise HTTPException(status_code=422, detail="Password must be at least 6 characters.")
    _exec("UPDATE users SET password_hash=%s, updated_at=NOW() WHERE id=%s",
          (_hash_password(body.password), g[0]["user_id"]))
    return {"ok": True, "id": gid}


@app.post("/api/guardians/{gid}/portal-link", dependencies=[Depends(require_auth)])
def guardian_portal_link(gid: str):
    """Admin: emite un link firmado al formulario de registro del portal (para que el
    acudiente fije su propia contraseña). El bot puede emitir el mismo token con el secreto
    compartido PORTAL_TOKEN_SECRET (JWT HS256, claims: sub=guardianId, typ='register')."""
    if not _q("SELECT id FROM guardians WHERE id=%s", (gid,)):
        raise HTTPException(status_code=404, detail="Guardian not found.")
    token = _make_register_token(gid)
    url = f"{PORTAL_REGISTER_URL}?token={token}" if PORTAL_REGISTER_URL else None
    return {"token": token, "url": url, "expiresInHours": REGISTER_TTL // 3600}


@app.get("/api/portal-links", dependencies=[Depends(require_auth)])
def portal_links_bulk(page: int = 1, page_limit: int = 50, only_missing: bool = True):
    """Admin: genera en lote los links de registro del portal (para onboardear a los
    acudientes YA creados). Por defecto solo los que aún no tienen contraseña (only_missing)."""
    page, page_limit, off = _pag(page, page_limit)
    where = "WHERE u.deleted_at IS NULL"
    if only_missing:
        where += " AND LEFT(u.password_hash, 6) <> 'pbkdf2'"
    total = _q(f"SELECT COUNT(*) c FROM guardians g JOIN users u ON u.id=g.user_id {where}")[0]["c"]
    rows = _q(f"""SELECT g.id, g.full_name AS name, u.phone_number AS phone,
                     LEFT(u.password_hash, 6) = 'pbkdf2' AS has_pw
                  FROM guardians g JOIN users u ON u.id=g.user_id {where}
                  ORDER BY g.full_name LIMIT %s OFFSET %s""", (page_limit, off))
    items = []
    for r in rows:
        tok = _make_register_token(r["id"])
        items.append({
            "guardianId": r["id"], "name": r["name"], "phone": r["phone"],
            "hasPassword": bool(r["has_pw"]),
            "token": tok, "url": (f"{PORTAL_REGISTER_URL}?token={tok}" if PORTAL_REGISTER_URL else None),
        })
    return _envelope(items, page, page_limit, total)


# ── Patients (CRUD) ──────────────────────────────────────────────────────────
_P_SELECT = """SELECT d.id, d.full_name AS name, d.birthday, d.css_number AS national_id,
    d.blood_type, d.weight_kg, d.known_conditions, d.allergies,
    d.insurance_company_id AS ins_id, ic.name AS ins_name, d.policy_number AS policy,
    g.id AS guardian_id, g.full_name AS guardian, u.phone_number AS phone, u.status AS ustatus,
    (SELECT MAX(cs.opened_at) FROM chat_sessions cs WHERE cs.dependent_id=d.id) AS last
    FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id
    JOIN guardians g ON g.id=gd.guardian_id JOIN users u ON u.id=g.user_id
    LEFT JOIN insurance_companies ic ON ic.id=d.insurance_company_id"""


def _patient_row(r: dict) -> dict:
    return {
        "id": r["id"], "name": r["name"], "nationalId": r["national_id"] or "", "age": _age(r["birthday"]),
        "birthDate": _clean(r["birthday"]), "bloodType": BLOOD_OUT.get(r.get("blood_type"), None),
        "weightKg": float(r["weight_kg"]) if r.get("weight_kg") is not None else None,
        "conditions": _split(r.get("known_conditions")), "allergies": _split(r.get("allergies")),
        "insurance": (
            {"id": r["ins_id"], "name": r["ins_name"], "policyNumber": r.get("policy") or None}
            if r.get("ins_id") else None
        ),
        "guardianId": r["guardian_id"], "guardian": r["guardian"], "phone": r["phone"],
        "status": PSTATUS_OUT.get(r["ustatus"], "pending"),
        "lastConsultation": _clean(r["last"]) if r["last"] else "",
    }


@app.get("/api/patients", dependencies=[Depends(require_auth)])
def patients(page: int = 1, page_limit: int = 20, q: str | None = Query(default=None)):
    page, page_limit, off = _pag(page, page_limit)
    where = "WHERE 1=1"
    args: list = []
    if q:
        where += " AND (d.full_name LIKE %s OR g.full_name LIKE %s)"
        args += [f"%{q}%"] * 2
    total = _q(f"SELECT COUNT(*) c FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id "
               f"JOIN guardians g ON g.id=gd.guardian_id {where}", tuple(args))[0]["c"]
    rows = _q(f"{_P_SELECT} {where} ORDER BY d.full_name LIMIT %s OFFSET %s", tuple(args + [page_limit, off]))
    return _envelope([_patient_row(r) for r in rows], page, page_limit, total)


@app.get("/api/patients/{pid}", dependencies=[Depends(require_auth)])
def patient_get(pid: str):
    rows = _q(f"{_P_SELECT} WHERE d.id=%s", (pid,))
    if not rows:
        raise HTTPException(status_code=404, detail="Patient not found.")
    return _patient_row(rows[0])


class PatientCreate(BaseModel):
    guardianId: str
    name: str
    birthDate: str
    weightKg: float | None = None
    bloodType: str | None = None
    conditions: list[str] | None = None
    allergies: list[str] | None = None
    insuranceId: int | None = None
    policyNumber: str | None = None


class PatientUpdate(BaseModel):
    name: str | None = None
    birthDate: str | None = None
    weightKg: float | None = None
    bloodType: str | None = None
    conditions: list[str] | None = None
    allergies: list[str] | None = None
    insuranceId: int | None = None
    policyNumber: str | None = None


@app.post("/api/patients", dependencies=[Depends(require_auth)], status_code=201)
def patient_create(body: PatientCreate):
    if not _q("SELECT id FROM guardians WHERE id=%s", (body.guardianId,)):
        raise HTTPException(status_code=404, detail="guardianId not found.")
    try:
        bday = date.fromisoformat(body.birthDate[:10])
    except ValueError:
        raise HTTPException(status_code=422, detail="birthDate must be YYYY-MM-DD.")
    blood = BLOOD_IN.get(body.bloodType) if body.bloodType else None
    pid = str(uuid.uuid4())
    _tx([
        ("""INSERT INTO dependents (id, full_name, birthday, blood_type, weight_kg, weight_input_unit,
             known_conditions, allergies, insurance_company_id, policy_number, created_at)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
         (pid, body.name.strip(), bday, blood, body.weightKg, "kg" if body.weightKg is not None else None,
          "; ".join(body.conditions) if body.conditions else None,
          "; ".join(body.allergies) if body.allergies else None, body.insuranceId, body.policyNumber)),
        ("INSERT INTO guardian_dependent (guardian_id, dependent_id, is_primary) VALUES (%s,%s,%s)",
         (body.guardianId, pid, 1)),
    ])
    return patient_get(pid)


@app.patch("/api/patients/{pid}", dependencies=[Depends(require_auth)])
def patient_update(pid: str, body: PatientUpdate):
    if not _q("SELECT id FROM dependents WHERE id=%s", (pid,)):
        raise HTTPException(status_code=404, detail="Patient not found.")
    sets, args = [], []
    if body.name is not None:
        sets.append("full_name=%s"); args.append(body.name.strip())
    if body.birthDate is not None:
        try:
            args.append(date.fromisoformat(body.birthDate[:10]))
        except ValueError:
            raise HTTPException(status_code=422, detail="birthDate must be YYYY-MM-DD.")
        sets.append("birthday=%s")
    if body.weightKg is not None:
        sets.append("weight_kg=%s"); args.append(body.weightKg)
    if body.bloodType is not None:
        sets.append("blood_type=%s"); args.append(BLOOD_IN.get(body.bloodType))
    if body.conditions is not None:
        sets.append("known_conditions=%s"); args.append("; ".join(body.conditions) or None)
    if body.allergies is not None:
        sets.append("allergies=%s"); args.append("; ".join(body.allergies) or None)
    if body.insuranceId is not None:
        sets.append("insurance_company_id=%s"); args.append(body.insuranceId)
    if body.policyNumber is not None:
        sets.append("policy_number=%s"); args.append(body.policyNumber or None)
    if sets:
        _exec(f"UPDATE dependents SET {', '.join(sets)} WHERE id=%s", tuple(args + [pid]))
    return patient_get(pid)


@app.delete("/api/patients/{pid}", dependencies=[Depends(require_auth)])
def patient_delete(pid: str):
    if not _q("SELECT id FROM dependents WHERE id=%s", (pid,)):
        raise HTTPException(status_code=404, detail="Patient not found.")
    _tx([
        ("UPDATE chat_sessions SET dependent_id=NULL WHERE dependent_id=%s", (pid,)),
        ("DELETE FROM guardian_dependent WHERE dependent_id=%s", (pid,)),
        ("DELETE FROM dependents WHERE id=%s", (pid,)),
    ])
    return {"deleted": True, "id": pid}


# ── Chats (paginated) ────────────────────────────────────────────────────────
@app.get("/api/chats", dependencies=[Depends(require_auth)])
def chats(page: int = 1, page_limit: int = 20):
    page, page_limit, off = _pag(page, page_limit)
    total = _q("SELECT COUNT(*) c FROM chat_sessions")[0]["c"]
    ses = _q(
        """SELECT cs.id, g.full_name AS guardian, d.full_name AS patient, u.phone_number AS phone,
               cl.name AS triage, cs.appointment_type, cs.summary AS ai_summary, cs.feedback_score AS rating,
               cs.status, cs.fsm_state, cs.opened_at AS started_at, cs.closed_at AS closed_at,
               (SELECT content FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
               (SELECT created_at FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS time
        FROM chat_sessions cs JOIN guardians g ON g.id=cs.guardian_id JOIN users u ON u.id=g.user_id
        LEFT JOIN dependents d ON d.id=cs.dependent_id LEFT JOIN classification cl ON cl.id=cs.classification_id
        ORDER BY cs.opened_at DESC LIMIT %s OFFSET %s""",
        (page_limit, off),
    )
    ids = [s["id"] for s in ses]
    by_s: dict = {}
    if ids:
        ph = ",".join(["%s"] * len(ids))
        msgs = _q(
            f"""SELECT m.session_id, m.sender_role, m.content, m.created_at, m.content_type,
                   GROUP_CONCAT(mf.flag_type) AS flags
                FROM messages m LEFT JOIN message_flags mf ON mf.message_id=m.id
                WHERE m.session_id IN ({ph})
                GROUP BY m.id, m.session_id, m.sender_role, m.content, m.created_at, m.content_type
                ORDER BY m.created_at ASC""",
            tuple(ids),
        )
        for m in msgs:
            by_s.setdefault(m["session_id"], []).append({
                "role": MSG_ROLE.get(m["sender_role"], "system"), "text": m["content"],
                "time": _clean(m["created_at"]), "type": (m["content_type"] or "text"),
                "alerts": (m["flags"].split(",") if m["flags"] else []),
            })

    def _st(s):
        return "closed" if s["status"] == "closed" else ("waiting" if s["fsm_state"] == "awaiting_user" else "active")

    items = [{
        "id": s["id"], "guardian": s["guardian"], "patient": s["patient"] or "", "phone": s["phone"],
        "triage": TRIAGE.get(s["triage"], "general"),
        "attentionType": "in_person" if (s["appointment_type"] or "").lower().startswith("pres") else "virtual",
        "aiSummary": s["ai_summary"] or None, "rating": int(s["rating"]) if s["rating"] is not None else None,
        "lastMessage": (s["last_message"] or "")[:200], "time": _clean(s["time"]) if s["time"] else "",
        "startedAt": _clean(s["started_at"]) if s["started_at"] else "",
        "closedAt": _clean(s["closed_at"]) if s["closed_at"] else None,
        "messages": by_s.get(s["id"], []), "status": _st(s),
    } for s in ses]
    return _envelope(items, page, page_limit, total)


# ── Plans (read catalog) ─────────────────────────────────────────────────────
@app.get("/api/plans", dependencies=[Depends(require_auth)])
def plans(page: int = 1, page_limit: int = 50):
    page, page_limit, off = _pag(page, page_limit)
    total = _q("SELECT COUNT(*) c FROM subscription_plans WHERE active=1")[0]["c"]
    rows = _q("SELECT id, name, max_dependents, price_monthly_usd, price_annual_usd FROM subscription_plans "
              "WHERE active=1 ORDER BY price_monthly_usd LIMIT %s OFFSET %s", (page_limit, off))
    items = [{"id": r["id"], "name": r["name"], "maxDependents": r["max_dependents"],
              "priceMonthly": float(r["price_monthly_usd"]), "priceAnnual": float(r["price_annual_usd"])} for r in rows]
    return _envelope(items, page, page_limit, total)


# ── Payments (paginated + create) ────────────────────────────────────────────
_PAY_SELECT = """SELECT p.id, p.provider_txn_id, g.full_name AS guardian, p.amount_usd AS amount,
    p.provider, p.billing_cycle, p.status, p.created_at, p.confirmed_at
    FROM payments p JOIN users u ON u.id=p.user_id LEFT JOIN guardians g ON g.user_id=u.id"""


def _payment_row(r: dict) -> dict:
    return {
        "id": r["provider_txn_id"] or r["id"], "guardian": r["guardian"] or "",
        "amount": float(r["amount"]) if r["amount"] is not None else 0,
        "method": PAY_METHOD.get(r["provider"], "yappy"), "plan": _plan(r["billing_cycle"]),
        "status": PAY_STATUS.get(r["status"], "pending"),
        "date": _clean(r["confirmed_at"] or r["created_at"]), "providerResponse": r["status"], "paymentType": "credit",
    }


@app.get("/api/payments", dependencies=[Depends(require_auth)])
def payments(page: int = 1, page_limit: int = 20):
    page, page_limit, off = _pag(page, page_limit)
    total = _q("SELECT COUNT(*) c FROM payments")[0]["c"]
    rows = _q(f"{_PAY_SELECT} ORDER BY p.created_at DESC LIMIT %s OFFSET %s", (page_limit, off))
    return _envelope([_payment_row(r) for r in rows], page, page_limit, total)


@app.get("/api/payments/{pid}", dependencies=[Depends(require_auth)])
def payment_get(pid: str):
    rows = _q(f"{_PAY_SELECT} WHERE p.id=%s OR p.provider_txn_id=%s", (pid, pid))
    if not rows:
        raise HTTPException(status_code=404, detail="Payment not found.")
    return _payment_row(rows[0])


class PaymentCreate(BaseModel):
    guardianId: str
    amount: float
    method: str | None = None
    billingCycle: str | None = None
    status: str | None = None
    planId: str | None = None
    txnId: str | None = None


@app.post("/api/payments", dependencies=[Depends(require_auth)], status_code=201)
def payment_create(body: PaymentCreate):
    g = _q("SELECT user_id FROM guardians WHERE id=%s", (body.guardianId,))
    if not g:
        raise HTTPException(status_code=404, detail="guardianId not found.")
    uid = g[0]["user_id"]
    cycle = body.billingCycle if body.billingCycle in ("monthly", "annual") else "monthly"
    provider = "yappy" if (body.method or "").lower() == "yappy" else "tilopay"
    status = body.status if body.status in ("pending", "confirmed", "failed", "refunded") else "confirmed"
    # resolve plan_id: explicit → by price match → cheapest active
    plan_id = None
    if body.planId and _q("SELECT id FROM subscription_plans WHERE id=%s", (body.planId,)):
        plan_id = body.planId
    if plan_id is None:
        col = "price_monthly_usd" if cycle == "monthly" else "price_annual_usd"
        m = _q(f"SELECT id FROM subscription_plans WHERE active=1 AND {col}=%s ORDER BY {col} LIMIT 1", (body.amount,))
        plan_id = m[0]["id"] if m else _q("SELECT id FROM subscription_plans WHERE active=1 ORDER BY price_monthly_usd LIMIT 1")[0]["id"]
    pid = str(uuid.uuid4())
    conf = "NOW()" if status == "confirmed" else "NULL"
    _guard_integrity(lambda: _exec(
        f"""INSERT INTO payments (id, user_id, plan_id, billing_cycle, provider, provider_txn_id,
             amount_usd, status, created_at, confirmed_at)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW(),{conf})""",
        (pid, uid, plan_id, cycle, provider, body.txnId, body.amount, status)))
    return payment_get(pid)


# ── Centers / hospitals (CRUD) ───────────────────────────────────────────────
TIERS = ("privado_tier1", "css", "publico_minsa")


def _center_row(r: dict) -> dict:
    nm = (r["name"] or "").lower()
    typ = "Clinic" if ("clínic" in nm or "clinic" in nm) else ("Emergency" if "urgenc" in nm else "Hospital")
    return {"id": r["id"], "name": r["name"], "type": typ, "city": r["city"] or "",
            "address": r["address"] or "", "phone": r["phone"] or "", "tier": r.get("tier"),
            "hours": "24/7", "recommended": bool(r["recommended"])}


@app.get("/api/centers", dependencies=[Depends(require_auth)])
def centers(page: int = 1, page_limit: int = 50):
    page, page_limit, off = _pag(page, page_limit)
    total = _q("SELECT COUNT(*) c FROM hospitals WHERE active=1")[0]["c"]
    rows = _q("SELECT id, name, city, address, phone, tier, recommended FROM hospitals "
              "WHERE active=1 ORDER BY name LIMIT %s OFFSET %s", (page_limit, off))
    return _envelope([_center_row(r) for r in rows], page, page_limit, total)


def _one_center(cid: str) -> dict:
    rows = _q("SELECT id, name, city, address, phone, tier, recommended FROM hospitals WHERE id=%s", (cid,))
    if not rows:
        raise HTTPException(status_code=404, detail="Center not found.")
    return _center_row(rows[0])


@app.get("/api/centers/{cid}", dependencies=[Depends(require_auth)])
def center_get(cid: str):
    return _one_center(cid)


class CenterCreate(BaseModel):
    name: str
    city: str
    address: str | None = None
    phone: str | None = None
    tier: str | None = None
    recommended: bool | None = None
    country: str | None = None


class CenterUpdate(BaseModel):
    name: str | None = None
    city: str | None = None
    address: str | None = None
    phone: str | None = None
    tier: str | None = None
    recommended: bool | None = None


@app.post("/api/centers", dependencies=[Depends(require_auth)], status_code=201)
def center_create(body: CenterCreate):
    tier = body.tier if body.tier in TIERS else "publico_minsa"
    cid = str(uuid.uuid4())
    _exec("""INSERT INTO hospitals (id, name, city, country, address, phone, tier, recommended, active, created_at)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,1,NOW())""",
          (cid, body.name.strip(), body.city.strip(), body.country or "Panamá", body.address, body.phone,
           tier, 1 if body.recommended else 0))
    return _one_center(cid)


@app.patch("/api/centers/{cid}", dependencies=[Depends(require_auth)])
def center_update(cid: str, body: CenterUpdate):
    if not _q("SELECT id FROM hospitals WHERE id=%s", (cid,)):
        raise HTTPException(status_code=404, detail="Center not found.")
    sets, args = [], []
    for col, val in (("name", body.name), ("city", body.city), ("address", body.address), ("phone", body.phone)):
        if val is not None:
            sets.append(f"{col}=%s"); args.append(val)
    if body.tier is not None:
        if body.tier not in TIERS:
            raise HTTPException(status_code=422, detail=f"tier must be one of {TIERS}.")
        sets.append("tier=%s"); args.append(body.tier)
    if body.recommended is not None:
        sets.append("recommended=%s"); args.append(1 if body.recommended else 0)
    if sets:
        _exec(f"UPDATE hospitals SET {', '.join(sets)} WHERE id=%s", tuple(args + [cid]))
    return _one_center(cid)


@app.delete("/api/centers/{cid}", dependencies=[Depends(require_auth)])
def center_delete(cid: str):
    if not _q("SELECT id FROM hospitals WHERE id=%s", (cid,)):
        raise HTTPException(status_code=404, detail="Center not found.")
    _exec("UPDATE hospitals SET active=0 WHERE id=%s", (cid,))
    return {"deleted": True, "id": cid}


# ── Insurances (CRUD) ────────────────────────────────────────────────────────
class NameIn(BaseModel):
    name: str


class InsuranceUpdate(BaseModel):
    name: str | None = None
    active: bool | None = None


@app.get("/api/insurances", dependencies=[Depends(require_auth)])
def insurances(page: int = 1, page_limit: int = 100):
    page, page_limit, off = _pag(page, page_limit)
    total = _q("SELECT COUNT(*) c FROM insurance_companies WHERE active=1")[0]["c"]
    rows = _q("SELECT id, name FROM insurance_companies WHERE active=1 ORDER BY name LIMIT %s OFFSET %s", (page_limit, off))
    return _envelope([{"id": r["id"], "name": r["name"]} for r in rows], page, page_limit, total)


@app.post("/api/insurances", dependencies=[Depends(require_auth)], status_code=201)
def insurance_create(body: NameIn):
    def _ins():
        _exec("INSERT INTO insurance_companies (name, active) VALUES (%s,1)", (body.name.strip(),))
        return _q("SELECT id, name FROM insurance_companies WHERE name=%s", (body.name.strip(),))[0]
    r = _guard_integrity(_ins)
    return {"id": r["id"], "name": r["name"]}


@app.patch("/api/insurances/{iid}", dependencies=[Depends(require_auth)])
def insurance_update(iid: int, body: InsuranceUpdate):
    if not _q("SELECT id FROM insurance_companies WHERE id=%s", (iid,)):
        raise HTTPException(status_code=404, detail="Insurance not found.")
    sets, args = [], []
    if body.name is not None:
        sets.append("name=%s"); args.append(body.name.strip())
    if body.active is not None:
        sets.append("active=%s"); args.append(1 if body.active else 0)
    if sets:
        _guard_integrity(lambda: _exec(f"UPDATE insurance_companies SET {', '.join(sets)} WHERE id=%s", tuple(args + [iid])))
    r = _q("SELECT id, name, active FROM insurance_companies WHERE id=%s", (iid,))[0]
    return {"id": r["id"], "name": r["name"], "active": bool(r["active"])}


@app.delete("/api/insurances/{iid}", dependencies=[Depends(require_auth)])
def insurance_delete(iid: int):
    if not _q("SELECT id FROM insurance_companies WHERE id=%s", (iid,)):
        raise HTTPException(status_code=404, detail="Insurance not found.")
    _exec("UPDATE insurance_companies SET active=0 WHERE id=%s", (iid,))  # soft delete (FK-safe)
    return {"deleted": True, "id": iid}


# ── Specialties (CRUD) ───────────────────────────────────────────────────────
@app.get("/api/specialties", dependencies=[Depends(require_auth)])
def specialties() -> list[str]:
    return _cached("specialties", 300, lambda: [r["name"] for r in _q("SELECT name FROM specialties ORDER BY name")])


@app.get("/api/specialties/all", dependencies=[Depends(require_auth)])
def specialties_all(page: int = 1, page_limit: int = 100):
    """Same catalog but with ids, for admin management (create/edit/delete)."""
    page, page_limit, off = _pag(page, page_limit)
    total = _q("SELECT COUNT(*) c FROM specialties")[0]["c"]
    rows = _q("SELECT id, name FROM specialties ORDER BY name LIMIT %s OFFSET %s", (page_limit, off))
    return _envelope([{"id": r["id"], "name": r["name"]} for r in rows], page, page_limit, total)


@app.post("/api/specialties", dependencies=[Depends(require_auth)], status_code=201)
def specialty_create(body: NameIn):
    def _ins():
        _exec("INSERT INTO specialties (name) VALUES (%s)", (body.name.strip(),))
        return _q("SELECT id, name FROM specialties WHERE name=%s", (body.name.strip(),))[0]
    r = _guard_integrity(_ins)
    _CACHE.pop("specialties", None)
    return {"id": r["id"], "name": r["name"]}


@app.patch("/api/specialties/{sid}", dependencies=[Depends(require_auth)])
def specialty_update(sid: int, body: NameIn):
    if not _q("SELECT id FROM specialties WHERE id=%s", (sid,)):
        raise HTTPException(status_code=404, detail="Specialty not found.")
    _guard_integrity(lambda: _exec("UPDATE specialties SET name=%s WHERE id=%s", (body.name.strip(), sid)))
    _CACHE.pop("specialties", None)
    return {"id": sid, "name": body.name.strip()}


@app.delete("/api/specialties/{sid}", dependencies=[Depends(require_auth)])
def specialty_delete(sid: int):
    if not _q("SELECT id FROM specialties WHERE id=%s", (sid,)):
        raise HTTPException(status_code=404, detail="Specialty not found.")
    _guard_integrity(lambda: _exec("DELETE FROM specialties WHERE id=%s", (sid,)))
    _CACHE.pop("specialties", None)
    return {"deleted": True, "id": sid}


# ── Usage / consumos (cached) ────────────────────────────────────────────────
@app.get("/api/usage/summary", dependencies=[Depends(require_auth)])
def usage_summary():
    def _f():
        r = _q("SELECT COUNT(*) calls, COALESCE(SUM(input_tokens),0) it, COALESCE(SUM(output_tokens),0) ot, "
               "COALESCE(SUM(cost_usd),0) cost, COALESCE(AVG(latency_ms),0) lat FROM ai_model_runs")[0]
        return {"calls": r["calls"], "inputTokens": int(r["it"]), "outputTokens": int(r["ot"]),
                "totalTokens": int(r["it"]) + int(r["ot"]), "costUsd": round(float(r["cost"]), 4),
                "avgLatencyMs": round(float(r["lat"]))}
    return _cached("usage:summary", 60, _f)


@app.get("/api/usage/by-day", dependencies=[Depends(require_auth)])
def usage_by_day():
    def _f():
        rows = _q("SELECT DATE(created_at) d, COUNT(*) calls, SUM(input_tokens+output_tokens) tokens, "
                  "SUM(cost_usd) cost FROM ai_model_runs GROUP BY DATE(created_at) ORDER BY d")
        return [{"date": _clean(r["d"]), "calls": r["calls"], "tokens": int(r["tokens"] or 0),
                 "costUsd": round(float(r["cost"] or 0), 4)} for r in rows]
    return _cached("usage:by-day", 60, _f)


@app.get("/api/usage/by-user", dependencies=[Depends(require_auth)])
def usage_by_user():
    def _f():
        rows = _q("""SELECT g.full_name AS guardian, u.phone_number AS phone, COUNT(*) calls,
                       SUM(r.input_tokens+r.output_tokens) tokens, SUM(r.cost_usd) cost
                    FROM ai_model_runs r JOIN chat_sessions cs ON cs.id=r.session_id
                    JOIN guardians g ON g.id=cs.guardian_id JOIN users u ON u.id=g.user_id
                    GROUP BY g.id, g.full_name, u.phone_number ORDER BY cost DESC""")
        return [{"guardian": r["guardian"], "phone": r["phone"], "calls": r["calls"],
                 "tokens": int(r["tokens"] or 0), "costUsd": round(float(r["cost"] or 0), 4)} for r in rows]
    return _cached("usage:by-user", 60, _f)


# ── Statistics (cached) ──────────────────────────────────────────────────────
@app.get("/api/stats/kpis", dependencies=[Depends(require_auth)])
def kpis():
    def _f():
        active = _q("SELECT COUNT(*) c FROM users WHERE status='active'")[0]["c"]
        children = _q("SELECT COUNT(*) c FROM dependents")[0]["c"]
        sm = _q("SELECT COUNT(*) c FROM chat_sessions WHERE opened_at >= DATE_FORMAT(NOW(),'%Y-%m-01')")[0]["c"]
        paid = _q("SELECT COUNT(DISTINCT user_id) c FROM payments WHERE status='confirmed'")[0]["c"]
        total = _q("SELECT COUNT(*) c FROM users")[0]["c"] or 1
        csat = _q("SELECT AVG(feedback_score) a FROM chat_sessions")[0]["a"]
        emg = _q("SELECT COUNT(*) c FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id WHERE cl.name='emergencia'")[0]["c"]
        ref = _q("SELECT COUNT(*) c FROM chat_sessions WHERE hospital_id IS NOT NULL OR appointment_type='presencial'")[0]["c"]
        rev = _q("SELECT COALESCE(SUM(amount_usd),0) s FROM payments WHERE status='confirmed' AND confirmed_at >= DATE_FORMAT(NOW(),'%Y-%m-01')")[0]["s"]
        return {"activeGuardians": active, "registeredChildren": children, "sessionsThisMonth": sm,
                "premiumConversion": round(paid / total * 100, 1), "csat": round(float(csat) / 5 * 100) if csat else 0,
                "emergenciesDetected": emg, "inPersonReferrals": ref, "revenueThisMonth": float(rev)}
    return _cached("stats:kpis", 60, _f)


_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


@app.get("/api/stats/sessions-per-month", dependencies=[Depends(require_auth)])
def sessions_per_month():
    def _f():
        rows = _q("SELECT YEAR(opened_at) y, MONTH(opened_at) m, COUNT(*) sessions FROM chat_sessions "
                  "WHERE opened_at IS NOT NULL GROUP BY YEAR(opened_at), MONTH(opened_at) ORDER BY y, m")
        prem = _q("SELECT YEAR(confirmed_at) y, MONTH(confirmed_at) m, COUNT(*) premium FROM payments "
                  "WHERE status='confirmed' AND confirmed_at IS NOT NULL GROUP BY YEAR(confirmed_at), MONTH(confirmed_at)")
        pmap = {(p["y"], p["m"]): p["premium"] for p in prem}
        return [{"month": _MONTHS[r["m"] - 1], "sessions": r["sessions"], "premium": pmap.get((r["y"], r["m"]), 0)} for r in rows]
    return _cached("stats:spm", 60, _f)


@app.get("/api/stats/triage", dependencies=[Depends(require_auth)])
def stats_triage():
    def _f():
        rows = _q("SELECT cl.name, COUNT(*) value FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id GROUP BY cl.name")
        order = {"general": 0, "urgente": 1, "emergencia": 2}
        rows.sort(key=lambda r: order.get(r["name"], 9))
        return [{"level": TRIAGE.get(r["name"], r["name"]).capitalize(), "value": r["value"],
                 "color": TRIAGE_COLOR.get(TRIAGE.get(r["name"], ""), "")} for r in rows]
    return _cached("stats:triage", 60, _f)


@app.get("/api/stats/plans", dependencies=[Depends(require_auth)])
def stats_plans():
    def _f():
        rows = _q("SELECT COALESCE((SELECT p.billing_cycle FROM payments p WHERE p.user_id=u.id AND p.status='confirmed' "
                  "ORDER BY p.confirmed_at DESC LIMIT 1),'free') AS cycle, COUNT(*) c FROM users u GROUP BY cycle")
        colors = {"free": "hsl(var(--triage-self))", "premium_monthly": "hsl(var(--accent))", "premium_annual": "hsl(var(--primary))"}
        agg: dict = {}
        for r in rows:
            agg[_plan(r["cycle"])] = agg.get(_plan(r["cycle"]), 0) + r["c"]
        return [{"plan": k, "users": v, "color": colors.get(k, "")} for k, v in agg.items()]
    return _cached("stats:plans", 60, _f)


@app.get("/api/stats/attention-type", dependencies=[Depends(require_auth)])
def stats_attention_type():
    def _f():
        pres = _q("SELECT COUNT(*) c FROM chat_sessions WHERE hospital_id IS NOT NULL OR appointment_type='presencial'")[0]["c"]
        tot = _q("SELECT COUNT(*) c FROM chat_sessions")[0]["c"]
        return [{"type": "virtual", "value": tot - pres}, {"type": "in_person", "value": pres}]
    return _cached("stats:att", 60, _f)


@app.get("/api/stats/csat", dependencies=[Depends(require_auth)])
def stats_csat():
    def _f():
        rows = _q("SELECT YEARWEEK(closed_at) yw, ROUND(AVG(feedback_score)/5*100) csat FROM chat_sessions "
                  "WHERE feedback_score IS NOT NULL AND closed_at IS NOT NULL GROUP BY YEARWEEK(closed_at) ORDER BY yw")
        return [{"week": f"W{i + 1}", "csat": int(r["csat"])} for i, r in enumerate(rows)]
    return _cached("stats:csat", 60, _f)


# ── Portal: registro (el acudiente fija SU contraseña vía link firmado) ───────
class PortalRegister(BaseModel):
    token: str
    password: str
    email: str | None = None


@app.get("/portal/register/{token}")
def portal_register_info(token: str):
    """Público: valida el link y devuelve datos para precargar el formulario de registro."""
    gid = _verify_register_token(token)
    rows = _q(
        """SELECT g.full_name AS name, u.phone_number AS phone, u.email,
               LEFT(u.password_hash, 6) = 'pbkdf2' AS has_pw
           FROM guardians g JOIN users u ON u.id=g.user_id WHERE g.id=%s""",
        (gid,),
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Guardian not found.")
    r = rows[0]
    return {"guardianId": gid, "name": r["name"], "phone": r["phone"],
            "email": r["email"], "hasPassword": bool(r["has_pw"])}


@app.post("/portal/register")
def portal_register(body: PortalRegister):
    """Público: el acudiente fija su contraseña desde el form del dashboard (link firmado).
    Activa la cuenta y habilita el login del portal."""
    gid = _verify_register_token(body.token)
    g = _q("SELECT user_id FROM guardians WHERE id=%s", (gid,))
    if not g:
        raise HTTPException(status_code=404, detail="Guardian not found.")
    if len(body.password or "") < 6:
        raise HTTPException(status_code=422, detail="Password must be at least 6 characters.")
    sets, args = ["password_hash=%s", "status='active'", "is_active=1"], [_hash_password(body.password)]
    if body.email:
        sets.append("email=%s"); args.append(body.email.strip())
    _exec(f"UPDATE users SET {', '.join(sets)}, updated_at=NOW() WHERE id=%s", tuple(args + [g[0]["user_id"]]))
    return {"ok": True, "guardianId": gid}


# ── Portal del acudiente (scoped: SOLO los datos del propio acudiente) ────────
@app.get("/portal/me")
def portal_me(gid: str = Depends(require_guardian)):
    """Perfil del acudiente autenticado + sus hijos (incluye seguro/plan)."""
    return _one_guardian(gid)


@app.get("/portal/children")
def portal_children(gid: str = Depends(require_guardian)):
    """Hijos del acudiente autenticado."""
    return _children_for([gid]).get(gid, [])


@app.get("/portal/patients")
def portal_patients(gid: str = Depends(require_guardian)):
    """Hijos (detalle de paciente) del acudiente autenticado."""
    rows = _q(f"{_P_SELECT} WHERE gd.guardian_id=%s ORDER BY d.full_name", (gid,))
    return [_patient_row(r) for r in rows]


@app.get("/portal/chats")
def portal_chats(gid: str = Depends(require_guardian)):
    """Historial de sesiones del acudiente autenticado (resumen, sin mensajes)."""
    rows = _q(
        """SELECT cs.id, d.full_name AS patient, cl.name AS triage, cs.appointment_type,
               cs.summary AS ai_summary, cs.feedback_score AS rating, cs.status, cs.fsm_state,
               cs.opened_at AS started_at, cs.closed_at AS closed_at
           FROM chat_sessions cs LEFT JOIN dependents d ON d.id=cs.dependent_id
           LEFT JOIN classification cl ON cl.id=cs.classification_id
           WHERE cs.guardian_id=%s ORDER BY cs.opened_at DESC""",
        (gid,),
    )

    def _st(s):
        return "closed" if s["status"] == "closed" else ("waiting" if s["fsm_state"] == "awaiting_user" else "active")

    return [{
        "id": s["id"], "patient": s["patient"] or "", "triage": TRIAGE.get(s["triage"], "general"),
        "attentionType": "in_person" if (s["appointment_type"] or "").lower().startswith("pres") else "virtual",
        "aiSummary": s["ai_summary"] or None, "rating": int(s["rating"]) if s["rating"] is not None else None,
        "startedAt": _clean(s["started_at"]) if s["started_at"] else "",
        "closedAt": _clean(s["closed_at"]) if s["closed_at"] else None, "status": _st(s),
    } for s in rows]


@app.get("/portal/payments")
def portal_payments(gid: str = Depends(require_guardian)):
    """Pagos del acudiente autenticado."""
    rows = _q(f"{_PAY_SELECT} WHERE u.id=(SELECT user_id FROM guardians WHERE id=%s) "
              "ORDER BY p.created_at DESC", (gid,))
    return [_payment_row(r) for r in rows]


# ── Future sections (paginated empty) ────────────────────────────────────────
def _empty_page(page: int, page_limit: int):
    page, page_limit, _ = _pag(page, page_limit)
    return _envelope([], page, page_limit, 0)


@app.get("/api/doctors", dependencies=[Depends(require_auth)])
def doctors(page: int = 1, page_limit: int = 20):
    return _empty_page(page, page_limit)


@app.get("/api/specialists", dependencies=[Depends(require_auth)])
def specialists(page: int = 1, page_limit: int = 20):
    return _empty_page(page, page_limit)


@app.get("/api/medications", dependencies=[Depends(require_auth)])
def medications(page: int = 1, page_limit: int = 20):
    return _empty_page(page, page_limit)


@app.get("/api/availability", dependencies=[Depends(require_auth)])
def availability(page: int = 1, page_limit: int = 20):
    return _empty_page(page, page_limit)


@app.get("/api/appointments", dependencies=[Depends(require_auth)])
def appointments(page: int = 1, page_limit: int = 20):
    return _empty_page(page, page_limit)


@app.get("/api/logs", dependencies=[Depends(require_auth)])
def logs(page: int = 1, page_limit: int = 20):
    return _empty_page(page, page_limit)
