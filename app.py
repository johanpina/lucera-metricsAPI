"""lucera-metrics — backend for the client dashboard.

Read + write over the Aiven database. English fields/routes. JWT auth with
refresh tokens. Paginated lists, CRUD for guardians/patients, usage (consumos)
endpoints, in-memory cache for stats/usage. Empty sections return paginated [].
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import io
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
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

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


# ── Usuarios del tablero: la BASE DE DATOS es la única fuente de verdad ───────
#
# Antes vivían en la variable de entorno METRICS_USERS. Ahora están en `users`, con
# `dashboard_access = 1`. Ese flag es explícito a propósito: hay acudientes con correo y
# contraseña de portal, y tener credenciales NO debe dar acceso al panel interno.
#
# Rol real (BD) → rol que consume el tablero. Se envían los dos: `role` mantiene el
# contrato que ya usa el front, `dbRole` permite permisos más finos más adelante.
ROLE_TO_DASHBOARD = {
    "super_admin": "Admin",
    "admin": "Admin",
    "soporte_tecnico": "Admin",
    "oficial_privacidad": "Admin",
    "doctor": "Doctor",
    "auditor_medico": "Doctor",
    "marketing": "Sales",
    "gerente_cuenta": "Sales",
    "guardian": "Guardian",
}


def _dashboard_user(email: str) -> dict | None:
    """Busca un operador del tablero por correo. Devuelve None si no puede entrar."""
    rows = _q(
        """SELECT id, email, full_name, role, status, password_hash, must_change_password
           FROM users
           WHERE email=%s AND deleted_at IS NULL AND status='active' AND dashboard_access=1""",
        (email,),
    )
    return rows[0] if rows else None


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
    """Verifica contra los dos formatos que conviven en `users.password_hash`.

    - `pbkdf2_sha256$iter$salt$hash` → el que se usa al fijar contraseñas nuevas.
    - `sha256$hash`                  → heredado de METRICS_USERS. Se conservó tal cual al
      migrar para no obligar a nadie a cambiar de contraseña; se reemplaza solo cuando el
      usuario la cambia (ahí pasa a PBKDF2).
    """
    stored = stored or ""
    if stored.startswith("sha256$"):
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored[7:])
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
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
    """Login del tablero. Autentica contra la tabla `users` (no contra variables de entorno)."""
    sub = (body.email or "").lower().strip()
    u = _dashboard_user(sub)
    if u is None or not _verify_password(body.password or "", u["password_hash"]):
        # Mismo mensaje si el correo no existe, si está inactivo o si no tiene acceso al
        # tablero: no revelamos cuál de las tres es.
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    name = u["full_name"] or sub.split("@")[0]
    role = ROLE_TO_DASHBOARD.get(u["role"], "Guardian")
    return {
        "access_token": _make_token(sub, name, role, "access", ACCESS_TTL, uid=u["id"], dbRole=u["role"]),
        "refresh_token": _make_token(sub, name, role, "refresh", REFRESH_TTL, uid=u["id"], dbRole=u["role"]),
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "user": {"id": u["id"], "email": sub, "name": name, "role": role, "dbRole": u["role"],
                 # Si viene true, el front debe mandar al usuario a cambiar la clave
                 # (entro con una temporal) via POST /api/users/me/password.
                 "mustChangePassword": bool(u.get("must_change_password"))},
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
        # Cédula del PACIENTE. Ya venía en /api/patients; faltaba aquí, así que el mismo hijo
        # salía con campos distintos según el endpoint.
        "idNumber": d.get("id_number"), "school": d.get("school"),
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
               d.policy_number AS policy, d.id_number, d.school
            FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id
            LEFT JOIN insurance_companies ic ON ic.id=d.insurance_company_id
            WHERE gd.guardian_id IN ({ph})""",
        tuple(gids),
    )
    out: dict = {}
    for d in deps:
        out.setdefault(d["guardian_id"], []).append(_child(d))
    return out


def _sub_state(expires) -> str:
    """Estado de la suscripción, resuelto en el backend para que el front no
    reimplemente la semántica del NULL:

    - `none`    → sin vencimiento (cortesía, validadores, altas previas a la columna)
    - `active`  → paga y vigente
    - `expired` → se le venció
    """
    if not expires:
        return "none"
    return "active" if expires > datetime.now() else "expired"


def _guardian_row(g: dict, kids: list[dict]) -> dict:
    insurance = (
        {"id": g["ins_id"], "name": g["ins_name"], "policyNumber": g.get("policy") or None}
        if g.get("ins_id") else None
    )
    return {
        "id": g["id"], "phone": g["phone"], "email": g["email"], "name": g["name"],
        "accountCode": g.get("account_code"), "gender": g.get("gender"),
        # Cedula del ACUDIENTE. Distinta de accountCode (la genera Lucera) y de la
        # idNumber de cada hijo, que es la del paciente.
        "idNumber": g.get("id_number"),
        "relationship": REL_OUT.get(g["rel"], "guardian"),
        "country": g.get("country") or _country(g["phone"]),   # nativo; fallback al prefijo del teléfono
        "province": g.get("province") or "", "address": g.get("address"),
        "city": g["city"] or g["province"] or "", "status": GSTATUS_OUT.get(g["ustatus"], "active"),
        "plan": _plan(g["cycle"]), "insurance": insurance, "registeredAt": _clean(g["created_at"]),
        # Vigencia de la suscripción. null = SIN VENCIMIENTO (cortesía, validadores, altas
        # previas a la columna); no confundir con vencida — para eso está subscriptionState.
        "subscriptionExpiresAt": _clean(g.get("expires_at")) if g.get("expires_at") else None,
        "subscriptionState": _sub_state(g.get("expires_at")),
        "portalEnabled": bool(g.get("portal_enabled")),   # ¿ya fijó contraseña del portal?
        "chats": int(g.get("chats") or 0),                # nº de consultas de la cuenta
        "children": kids,
    }


_G_SELECT = """SELECT g.id, g.full_name AS name, g.relationship_type AS rel, g.country, g.city, g.province,
    g.account_code, g.gender, g.address, g.id_number,
    g.insurance_company_id AS ins_id, ic.name AS ins_name, g.policy_number AS policy,
    u.phone_number AS phone, u.email, u.status AS ustatus, u.created_at,
    u.subscription_expires_at AS expires_at,
    LEFT(u.password_hash, 6) = 'pbkdf2' AS portal_enabled,
    (SELECT COUNT(*) FROM chat_sessions cs WHERE cs.guardian_id=g.id) AS chats,
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
        # Sin plan pago no hay qué vencer. NULL = sin vencimiento, como antes de la columna.
        _exec("UPDATE users SET subscription_expires_at=NULL WHERE id=%s", (uid,))
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
    # Asignar el plan desde el panel NO pasa por el bot, así que la vigencia se fija también
    # aquí. Misma regla que app/services/subscriptions.py del bot: encadena si sigue vigente,
    # cuenta desde hoy si venció o nunca tuvo. INTERVAL de MySQL ya recorta el fin de mes
    # (31-ene + 1 MONTH = 28-feb), igual que el _add_months del bot.
    _exec(
        "UPDATE users SET subscription_expires_at = DATE_ADD("
        "  GREATEST(COALESCE(subscription_expires_at, NOW()), NOW()), "
        f"  INTERVAL 1 {'YEAR' if cycle == 'annual' else 'MONTH'}) "
        "WHERE id=%s",
        (uid,),
    )


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
    idNumber: str | None = None      # cedula del acudiente


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
             insurance_company_id, policy_number, id_number, created_at)
             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
         (gid, uid, body.name.strip(), rel, body.address, body.country, body.city, body.province,
          body.insuranceId, body.policyNumber, (body.idNumber or "").strip() or None)),
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
    address: str | None = None       # dirección del acudiente
    idNumber: str | None = None      # cedula del acudiente
    gender: str | None = None        # femenino|masculino|otro|prefiere_no_decir
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
    if body.address is not None:
        gsets.append("address=%s"); gargs.append(body.address.strip() or None)
    if body.gender is not None:
        if body.gender not in ("femenino", "masculino", "otro", "prefiere_no_decir"):
            raise HTTPException(422, "gender must be: femenino|masculino|otro|prefiere_no_decir")
        gsets.append("gender=%s"); gargs.append(body.gender)
    if body.policyNumber is not None:
        gsets.append("policy_number=%s"); gargs.append(body.policyNumber or None)
    if body.idNumber is not None:
        gsets.append("id_number=%s"); gargs.append(body.idNumber.strip() or None)
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
    d.id_number, d.school,
    d.blood_type, d.weight_kg, d.known_conditions, d.allergies,
    d.insurance_company_id AS ins_id, ic.name AS ins_name, d.policy_number AS policy,
    g.id AS guardian_id, g.full_name AS guardian, g.account_code, g.address,
    u.phone_number AS phone, u.status AS ustatus,
    (SELECT MAX(cs.opened_at) FROM chat_sessions cs WHERE cs.dependent_id=d.id) AS last,
    (SELECT COUNT(*) FROM chat_sessions cs WHERE cs.dependent_id=d.id) AS chats
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
        # nationalId = número de CSS (seguridad social). idNumber = cédula/documento del paciente.
        "idNumber": r.get("id_number"), "school": r.get("school"),
        "guardianId": r["guardian_id"], "guardian": r["guardian"], "phone": r["phone"],
        "accountCode": r.get("account_code"), "address": r.get("address"),
        "status": PSTATUS_OUT.get(r["ustatus"], "pending"),
        "chats": int(r.get("chats") or 0),                 # nº de consultas del paciente
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
    idNumber: str | None = None   # cédula/documento del paciente
    school: str | None = None     # centro educativo


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
    if body.idNumber is not None:
        sets.append("id_number=%s"); args.append(body.idNumber or None)
    if body.school is not None:
        sets.append("school=%s"); args.append(body.school or None)
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
def chats(page: int = 1, page_limit: int = 20, derivation: str | None = None,
          insurance_id: int | None = None, date_from: str | None = None, date_to: str | None = None,
          guardian_id: str | None = None):
    """Chats con filtros.

    `derivation`: home | appointment | emergency (mapea a classification general/urgente/emergencia).
    `insurance_id`: seguro del acudiente o, si no tiene, del paciente.
    """
    page, page_limit, off = _pag(page, page_limit)
    where, args = ["1=1"], []
    if derivation:
        cls = {v: k for k, v in DERIVATION.items()}.get(derivation)
        if cls is None:
            raise HTTPException(422, "derivation must be one of: home, appointment, emergency")
        where.append("cl.name = %s")
        args.append(cls)
    if insurance_id is not None:
        where.append("COALESCE(g.insurance_company_id, d.insurance_company_id) = %s")
        args.append(insurance_id)
    if date_from:
        where.append("cs.opened_at >= %s")
        args.append(date_from)
    if date_to:
        where.append("cs.opened_at < DATE_ADD(%s, INTERVAL 1 DAY)")
        args.append(date_to)
    if guardian_id:
        where.append("cs.guardian_id = %s")
        args.append(guardian_id)
    w = " AND ".join(where)
    _joins = ("""FROM chat_sessions cs JOIN guardians g ON g.id=cs.guardian_id JOIN users u ON u.id=g.user_id
        LEFT JOIN dependents d ON d.id=cs.dependent_id LEFT JOIN classification cl ON cl.id=cs.classification_id""")

    total = _q(f"SELECT COUNT(*) c {_joins} WHERE {w}", tuple(args))[0]["c"]
    ses = _q(
        f"""SELECT cs.id, g.full_name AS guardian, g.account_code, d.full_name AS patient,
               u.phone_number AS phone, cs.guardian_id, cs.dependent_id,
               cl.name AS triage, cs.appointment_type, cs.summary AS ai_summary, cs.feedback_score AS rating,
               cs.status, cs.fsm_state, cs.opened_at AS started_at, cs.closed_at AS closed_at,
               cs.doctor_note, cs.reviewed_by, cs.reviewed_at, cs.tech_failure,
               (SELECT ic.name FROM insurance_companies ic
                  WHERE ic.id = COALESCE(g.insurance_company_id, d.insurance_company_id)) AS insurance,
               (SELECT content FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
               (SELECT created_at FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS time
        {_joins} WHERE {w}
        ORDER BY cs.opened_at DESC LIMIT %s OFFSET %s""",
        tuple(args) + (page_limit, off),
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
        "guardianId": s["guardian_id"], "patientId": s["dependent_id"], "accountCode": s["account_code"],
        "insurance": s["insurance"],
        "triage": TRIAGE.get(s["triage"], "general"),
        # Derivación clínica (casa/cita/urgencias). NO confundir con attentionType, que es la
        # modalidad (virtual/presencial) — son dos ejes distintos.
        "derivation": DERIVATION.get(s["triage"], "home") if s["triage"] else None,
        "attentionType": "in_person" if (s["appointment_type"] or "").lower().startswith("pres") else "virtual",
        "aiSummary": s["ai_summary"] or None, "rating": int(s["rating"]) if s["rating"] is not None else None,
        "doctorNote": s["doctor_note"], "reviewedBy": s["reviewed_by"],
        "reviewedAt": _clean(s["reviewed_at"]) if s["reviewed_at"] else None,
        "techFailure": bool(s["tech_failure"]),
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


# ═════════════════════════════════════════════════════════════════════════════
# BACKLOG DEL TABLERO — agregaciones nuevas
#
# Vocabulario de derivación (IMPORTANTE): el tablero habla de "casa / cita / urgencias".
# Eso NO es `attention_type` (virtual vs presencial, que es otro eje), sino `classification`:
#     general → home  ·  urgente → appointment  ·  emergencia → emergency
# ═════════════════════════════════════════════════════════════════════════════
DERIVATION = {"general": "home", "urgente": "appointment", "emergencia": "emergency"}

# Una cuenta es "premium" si tiene al menos un pago confirmado.
_PREMIUM_SQL = "EXISTS (SELECT 1 FROM payments p WHERE p.user_id=u.id AND p.status='confirmed')"

# ¿La sesión recibió al menos una orientación del bot?
#
# OJO con "abandonada": cerrar por inactividad NO es abandono. En WhatsApp la gente casi
# nunca se despide — recibe su respuesta y deja de escribir, y el barredor cierra la sesión
# a los 30 min. Contar esas como abandonadas inflaba el indicador (76 de 143) y hundía el
# completion rate sin motivo. Abandonada = el usuario escribió y NUNCA obtuvo respuesta.
# Las cerradas por inactividad cuentan como CERRADAS, igual que antes.
_ANSWERED = ("EXISTS (SELECT 1 FROM messages m WHERE m.session_id=cs.id "
             "AND m.sender_role IN ('bot','assistant'))")


def _month_series(rows: list[dict]) -> list[dict]:
    return [{"month": str(r["month"]), "value": int(r["value"] or 0)} for r in rows]


@app.get("/api/geo", dependencies=[Depends(require_auth)])
def geo():
    """Catálogo país → provincias/departamentos (Panamá, Colombia, Argentina)."""
    def _f():
        cs = _q("SELECT id, code, name, phone_code FROM countries WHERE active=1 ORDER BY name")
        st = _q("SELECT country_id, name FROM states WHERE active=1 ORDER BY name")
        by: dict = {}
        for s in st:
            by.setdefault(s["country_id"], []).append(s["name"])
        return [{"code": c["code"], "name": c["name"], "phoneCode": c["phone_code"],
                 "states": by.get(c["id"], [])} for c in cs]
    return _cached("geo", 3600, _f)


@app.get("/api/stats/summary", dependencies=[Depends(require_auth)])
def stats_summary():
    """North Star del Resumen: cuentas, conversión, revenue, CSAT, uso y seguridad."""
    def _f():
        acc = _q(
            f"""SELECT COUNT(*) total, SUM(u.status='active') active, SUM({_PREMIUM_SQL}) premium
                FROM users u WHERE u.role='guardian' AND u.deleted_at IS NULL"""
        )[0]
        total = int(acc["total"] or 0)
        premium = int(acc["premium"] or 0)
        revenue = _q("SELECT COALESCE(SUM(amount_usd),0) v FROM payments WHERE status='confirmed'")[0]["v"]
        ses = _q(
            f"""SELECT COUNT(*) total, SUM({_ANSWERED}) completed,
                       SUM(NOT {_ANSWERED}) abandoned FROM chat_sessions cs"""
        )[0]
        ses_total = int(ses["total"] or 0)
        emerg = int(_q(
            "SELECT COUNT(*) c FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id "
            "WHERE cl.name='emergencia'"
        )[0]["c"] or 0)
        csat = _q("SELECT AVG(feedback_score) v FROM chat_sessions WHERE feedback_score IS NOT NULL")[0]["v"]
        # Reported ER Rate: de las urgencias donde el acudiente RESPONDIÓ el seguimiento,
        # cuántas confirmaron haber acudido. El denominador son las respondidas, no todas
        # las urgencias: "sin respuesta" no significa "no fue".
        er = _q(
            """SELECT COUNT(*) respondidas, SUM(cs.er_confirmed=1) fueron
               FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id
               WHERE cl.name='emergencia' AND cs.er_confirmed IS NOT NULL"""
        )[0]
        er_resp = int(er["respondidas"] or 0)
        er_si = int(er["fueron"] or 0)
        return {
            "accounts": {
                "total": total, "active": int(acc["active"] or 0),
                "free": total - premium, "premium": premium,
                "conversionRate": round(premium / total * 100, 1) if total else 0.0,
            },
            "revenueUsd": float(revenue or 0),
            # null = aún no se recoge feedback (falta la encuesta post-consulta en el bot).
            "csat": round(float(csat) / 5 * 100, 1) if csat is not None else None,
            "usage": {
                "sessions": ses_total,
                "sessionCompletionRate": round(int(ses["completed"] or 0) / ses_total * 100, 1) if ses_total else 0.0,
                "abandoned": int(ses["abandoned"] or 0),
            },
            "safety": {
                "redFlagsToEmergency": emerg,
                "redFlagRate": round(emerg / ses_total * 100, 1) if ses_total else 0.0,
                # null mientras nadie haya respondido todavía el seguimiento.
                "reportedErRate": round(er_si / er_resp * 100, 1) if er_resp else None,
                "erConfirmed": er_si,        # confirmaron que acudieron
                "erAnswered": er_resp,       # respondieron el seguimiento (denominador)
            },
        }
    return _cached("stats:summary", 60, _f)


@app.get("/api/stats/accounts", dependencies=[Depends(require_auth)])
def stats_accounts():
    """Sección Cuentas: captación mensual y distribución por plan, aseguradora, país y género."""
    def _f():
        by_month = _q(
            "SELECT DATE_FORMAT(created_at,'%Y-%m') month, COUNT(*) value FROM users "
            "WHERE role='guardian' AND deleted_at IS NULL GROUP BY month ORDER BY month"
        )
        by_plan = _q(
            f"""SELECT CASE WHEN {_PREMIUM_SQL} THEN 'premium' ELSE 'free' END plan, COUNT(*) value
                FROM users u WHERE u.role='guardian' AND u.deleted_at IS NULL GROUP BY plan"""
        )
        by_ins = _q(
            "SELECT COALESCE(ic.name,'Sin seguro') name, COUNT(*) value FROM guardians g "
            "LEFT JOIN insurance_companies ic ON ic.id=g.insurance_company_id GROUP BY name ORDER BY value DESC"
        )
        by_country = _q(
            "SELECT COALESCE(NULLIF(country,''),'Sin definir') name, COUNT(*) value "
            "FROM guardians GROUP BY name ORDER BY value DESC"
        )
        by_gender = _q(
            "SELECT COALESCE(gender,'prefiere_no_decir') name, COUNT(*) value "
            "FROM guardians GROUP BY name ORDER BY value DESC"
        )
        return {
            "byMonth": _month_series(by_month),
            "byPlan": [{"plan": r["plan"], "value": int(r["value"])} for r in by_plan],
            "byInsurance": [{"name": r["name"], "value": int(r["value"])} for r in by_ins],
            "byCountry": [{"name": r["name"], "value": int(r["value"])} for r in by_country],
            "byGender": [{"name": r["name"], "value": int(r["value"])} for r in by_gender],
        }
    return _cached("stats:accounts", 60, _f)


@app.get("/api/stats/children", dependencies=[Depends(require_auth)])
def stats_children():
    """Sección Niños: total, captación mensual, promedio por cuenta y pirámide de edad."""
    def _f():
        total = int(_q("SELECT COUNT(*) c FROM dependents")[0]["c"] or 0)
        accounts = int(_q("SELECT COUNT(*) c FROM guardians")[0]["c"] or 0)
        by_month = _q(
            "SELECT DATE_FORMAT(created_at,'%Y-%m') month, COUNT(*) value FROM dependents "
            "GROUP BY month ORDER BY month"
        )
        by_age = _q(
            """SELECT CASE
                    WHEN TIMESTAMPDIFF(YEAR, birthday, CURDATE()) < 1  THEN '0-1'
                    WHEN TIMESTAMPDIFF(YEAR, birthday, CURDATE()) < 3  THEN '1-2'
                    WHEN TIMESTAMPDIFF(YEAR, birthday, CURDATE()) < 6  THEN '3-5'
                    WHEN TIMESTAMPDIFF(YEAR, birthday, CURDATE()) < 12 THEN '6-11'
                    ELSE '12+' END AS bucket, COUNT(*) value
               FROM dependents GROUP BY bucket"""
        )
        order = {"0-1": 0, "1-2": 1, "3-5": 2, "6-11": 3, "12+": 4}
        by_age.sort(key=lambda r: order.get(r["bucket"], 9))
        return {
            "total": total,
            "perAccountAvg": round(total / accounts, 2) if accounts else 0.0,
            "byMonth": _month_series(by_month),
            "byAge": [{"range": r["bucket"], "value": int(r["value"])} for r in by_age],
        }
    return _cached("stats:children", 60, _f)


@app.get("/api/stats/chats", dependencies=[Depends(require_auth)])
def stats_chats():
    """Sección Chats: estados, derivaciones (casa/cita/urgencias) y las 3 curvas por mes."""
    def _f():
        # Cerradas = TODAS las cerradas, incluidas las de inactividad (como estaba antes).
        st = _q(
            f"""SELECT COUNT(*) total, SUM(status='active') open_,
                       SUM(status='closed') closed_,
                       SUM(NOT {_ANSWERED}) abandoned FROM chat_sessions cs"""
        )[0]
        total = int(st["total"] or 0)
        by_month = _q(
            "SELECT DATE_FORMAT(opened_at,'%Y-%m') month, COUNT(*) value FROM chat_sessions "
            "GROUP BY month ORDER BY month"
        )
        deriv = _q(
            "SELECT cl.name, COUNT(*) value FROM chat_sessions cs "
            "JOIN classification cl ON cl.id=cs.classification_id GROUP BY cl.name"
        )
        curves = _q(
            "SELECT DATE_FORMAT(cs.opened_at,'%Y-%m') month, cl.name, COUNT(*) value "
            "FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id "
            "GROUP BY month, cl.name ORDER BY month"
        )
        months = sorted({str(r["month"]) for r in curves})
        idx = {(str(r["month"]), r["name"]): int(r["value"]) for r in curves}
        accounts = int(_q("SELECT COUNT(*) c FROM guardians")[0]["c"] or 0)
        emerg = sum(int(r["value"]) for r in deriv if r["name"] == "emergencia")
        return {
            "total": total,
            "byState": {"open": int(st["open_"] or 0), "closed": int(st["closed_"] or 0),
                        "abandoned": int(st["abandoned"] or 0), "total": total},
            "byMonth": _month_series(by_month),
            "byDerivation": [
                {"type": DERIVATION.get(r["name"], r["name"]), "value": int(r["value"]),
                 "percent": round(int(r["value"]) / total * 100, 1) if total else 0.0}
                for r in deriv
            ],
            "derivationCurves": [
                {"month": m, "home": idx.get((m, "general"), 0),
                 "appointment": idx.get((m, "urgente"), 0), "emergency": idx.get((m, "emergencia"), 0)}
                for m in months
            ],
            "perAccountAvg": round(total / accounts, 2) if accounts else 0.0,
            "emergenciesPerAccountAvg": round(emerg / accounts, 2) if accounts else 0.0,
        }
    return _cached("stats:chats", 60, _f)


@app.get("/api/stats/performance", dependencies=[Depends(require_auth)])
def stats_performance():
    """Sección Desempeño. Ojo: `churnRate` es una APROXIMACIÓN por inactividad (ver `note`)."""
    def _f():
        ttfc = _q(
            """SELECT AVG(TIMESTAMPDIFF(MINUTE, u.created_at, f.first_open)) v FROM users u
               JOIN guardians g ON g.user_id=u.id
               JOIN (SELECT guardian_id, MIN(opened_at) first_open FROM chat_sessions GROUP BY guardian_id) f
                 ON f.guardian_id=g.id"""
        )[0]["v"]
        ttr = _q(
            "SELECT AVG(TIMESTAMPDIFF(MINUTE, opened_at, closed_at)) v FROM chat_sessions "
            "WHERE closed_at IS NOT NULL AND fsm_state IN ('resolved','closed_user')"
        )[0]["v"]
        accounts = int(_q("SELECT COUNT(*) c FROM guardians")[0]["c"] or 0)
        active30 = int(_q(
            "SELECT COUNT(DISTINCT guardian_id) c FROM chat_sessions "
            "WHERE opened_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
        )[0]["c"] or 0)
        idle60 = int(_q(
            """SELECT COUNT(*) c FROM guardians g WHERE NOT EXISTS (
                 SELECT 1 FROM chat_sessions cs WHERE cs.guardian_id=g.id
                 AND cs.opened_at >= DATE_SUB(NOW(), INTERVAL 60 DAY))"""
        )[0]["c"] or 0)
        free_capped = int(_q(
            f"""SELECT COUNT(*) c FROM users u
                WHERE u.role='guardian' AND u.deleted_at IS NULL
                  AND u.free_sessions_used > 0 AND NOT {_PREMIUM_SQL}"""
        )[0]["c"] or 0)
        tech = int(_q("SELECT COUNT(*) c FROM chat_sessions WHERE tech_failure=1")[0]["c"] or 0)
        ses_total = int(_q("SELECT COUNT(*) c FROM chat_sessions")[0]["c"] or 0)
        return {
            "timeToFirstConsultMin": round(float(ttfc), 1) if ttfc is not None else None,
            "timeToResolutionMin": round(float(ttr), 1) if ttr is not None else None,
            "activeAccountRate": round(active30 / accounts * 100, 1) if accounts else 0.0,
            "churnRate": round(idle60 / accounts * 100, 1) if accounts else 0.0,
            "freeLimitNoConversion": free_capped,
            "techFailureSessions": tech,
            "techFailureRate": round(tech / ses_total * 100, 2) if ses_total else 0.0,
            # Falta definir qué cuenta como onboarding "completo" (¿registro + hijo + 1 consulta?).
            "onboardingCompletionRate": None,
            "note": "churnRate = cuentas sin ninguna consulta en los últimos 60 días "
                    "(aproximación por inactividad, no por cancelación de pago).",
        }
    return _cached("stats:performance", 60, _f)


@app.get("/api/stats/insurance", dependencies=[Depends(require_auth)])
def stats_insurance(insurance_id: int | None = None, date_from: str | None = None,
                    date_to: str | None = None):
    """Seguros Médicos con filtros. Barras segmentadas casa/cita/urgencias por aseguradora.

    El seguro se toma del ACUDIENTE (la póliza suele ser suya) y, si no tiene, del paciente.
    """
    key = f"stats:ins:{insurance_id}:{date_from}:{date_to}"

    def _f():
        where, args = ["1=1"], []
        if insurance_id is not None:
            where.append("COALESCE(g.insurance_company_id, d.insurance_company_id) = %s")
            args.append(insurance_id)
        if date_from:
            where.append("cs.opened_at >= %s")
            args.append(date_from)
        if date_to:
            where.append("cs.opened_at < DATE_ADD(%s, INTERVAL 1 DAY)")
            args.append(date_to)
        w = " AND ".join(where)
        rows = _q(
            f"""SELECT COALESCE(ic.name,'Sin seguro') name, cl.name AS cls, COUNT(*) value
                FROM chat_sessions cs
                JOIN guardians g ON g.id=cs.guardian_id
                LEFT JOIN dependents d ON d.id=cs.dependent_id
                LEFT JOIN insurance_companies ic
                       ON ic.id = COALESCE(g.insurance_company_id, d.insurance_company_id)
                LEFT JOIN classification cl ON cl.id=cs.classification_id
                WHERE {w} GROUP BY name, cls""",
            tuple(args),
        )
        agg: dict = {}
        for r in rows:
            e = agg.setdefault(r["name"], {"insurance": r["name"], "home": 0, "appointment": 0,
                                           "emergency": 0, "total": 0})
            n = int(r["value"])
            e["total"] += n
            if r["cls"]:
                e[DERIVATION.get(r["cls"], "home")] += n
        items = sorted(agg.values(), key=lambda x: -x["total"])
        return {
            "items": items,
            "totals": {"consultations": sum(i["total"] for i in items),
                       "emergencies": sum(i["emergency"] for i in items)},
            "filters": {"insuranceId": insurance_id, "dateFrom": date_from, "dateTo": date_to},
        }
    return _cached(key, 60, _f)


@app.get("/api/accounts", dependencies=[Depends(require_auth)])
def accounts(page: int = 1, page_limit: int = 20, q: str | None = None):
    """Sección Cuentas: una fila por familia, con código, plan, pagos, hijos y consultas."""
    page, page_limit, off = _pag(page, page_limit)
    where, args = ["u.role='guardian'", "u.deleted_at IS NULL"], []
    if q:
        where.append("(g.full_name LIKE %s OR g.account_code LIKE %s OR u.phone_number LIKE %s)")
        args += [f"%{q}%"] * 3
    w = " AND ".join(where)
    total = _q(f"SELECT COUNT(*) c FROM guardians g JOIN users u ON u.id=g.user_id WHERE {w}",
               tuple(args))[0]["c"]
    rows = _q(
        f"""SELECT g.id, g.account_code, g.full_name, g.gender, g.country, g.province, g.city,
                   g.address, u.phone_number, u.email, u.status, u.created_at, ic.name AS insurance,
                   u.subscription_expires_at AS expires_at, g.id_number,
                   (SELECT COUNT(*) FROM guardian_dependent gd WHERE gd.guardian_id=g.id) children,
                   (SELECT COUNT(*) FROM chat_sessions cs WHERE cs.guardian_id=g.id) chats,
                   (SELECT p.status FROM payments p WHERE p.user_id=u.id
                      ORDER BY p.created_at DESC LIMIT 1) pay_status,
                   (SELECT sp.name FROM payments p JOIN subscription_plans sp ON sp.id=p.plan_id
                      WHERE p.user_id=u.id AND p.status='confirmed'
                      ORDER BY p.confirmed_at DESC LIMIT 1) plan
            FROM guardians g JOIN users u ON u.id=g.user_id
            LEFT JOIN insurance_companies ic ON ic.id=g.insurance_company_id
            WHERE {w} ORDER BY u.created_at DESC LIMIT %s OFFSET %s""",
        tuple(args) + (page_limit, off),
    )
    items = [{
        "id": r["id"], "accountCode": r["account_code"], "guardian": r["full_name"],
        "idNumber": r["id_number"],   # cedula del acudiente
        "gender": r["gender"], "phone": r["phone_number"], "email": r["email"],
        "country": r["country"], "province": r["province"], "city": r["city"], "address": r["address"],
        "insurance": r["insurance"], "status": r["status"], "plan": r["plan"] or "free",
        "paymentStatus": r["pay_status"], "children": int(r["children"] or 0),
        "chats": int(r["chats"] or 0), "createdAt": _clean(r["created_at"]),
        # null = sin vencimiento; usar subscriptionState para pintar el estado.
        "subscriptionExpiresAt": _clean(r["expires_at"]) if r["expires_at"] else None,
        "subscriptionState": _sub_state(r["expires_at"]),
    } for r in rows]
    return _envelope(items, page, page_limit, total)


@app.get("/api/users", dependencies=[Depends(require_auth)])
def users_internal(page: int = 1, page_limit: int = 20, role: str | None = None,
                   dashboard_only: bool = False, q: str | None = None):
    """Usuarios internos: todo lo que NO es acudiente (admin, doctor, ventas, auditor…).

    `dashboard_only=true` incluye además a los acudientes con acceso al tablero
    (hoy Ana y David), que es la lista real de "quién puede entrar".
    """
    page, page_limit, off = _pag(page, page_limit)
    where, args = ["u.deleted_at IS NULL"], []
    where.append("u.dashboard_access=1" if dashboard_only else "u.role <> 'guardian'")
    if role:
        where.append("u.role = %s")
        args.append(role)
    if q:
        where.append("(u.email LIKE %s OR u.full_name LIKE %s)")
        args += [f"%{q}%"] * 2
    w = " AND ".join(where)
    total = _q(f"SELECT COUNT(*) c FROM users u WHERE {w}", tuple(args))[0]["c"]
    rows = _q(
        f"""SELECT u.id, u.email, u.phone_number, u.full_name, u.role, u.status, u.is_active,
                   u.dashboard_access, u.password_hash, u.created_at, u.must_change_password,
                   ud.license_id, ud.medical_specialty
            FROM users u LEFT JOIN users_doctor ud ON ud.user_id=u.id
            WHERE {w} ORDER BY u.created_at DESC LIMIT %s OFFSET %s""",
        tuple(args) + (page_limit, off),
    )
    return _envelope([_user_row(r) for r in rows], page, page_limit, total)


_INTERNAL_ROLES = ("super_admin", "admin", "doctor", "auditor_medico", "marketing",
                   "gerente_cuenta", "oficial_privacidad", "soporte_tecnico")

# Etiqueta legible de cada rol. Vive aquí y se sirve por /api/roles para que el tablero no
# tenga que mantener su propia copia (y quedar desfasado cuando se agregue un rol).
_ROLE_LABELS = {
    "super_admin":        "Superadministrador",
    "admin":              "Administrador",
    "doctor":             "Médico",
    "auditor_medico":     "Auditor médico",
    "marketing":          "Marketing",
    "gerente_cuenta":     "Gerente de cuenta",
    "oficial_privacidad": "Oficial de privacidad",
    "soporte_tecnico":    "Soporte técnico",
}
_MIN_PASSWORD = 8


def _check_password_strength(pw: str) -> None:
    """Mínimos de contraseña. Deliberadamente simples: largo y que no sea de las obvias.
    Reglas de composición (mayúscula+número+símbolo) empujan a la gente a 'Password1!'."""
    if len(pw) < _MIN_PASSWORD:
        raise HTTPException(422, f"password must be at least {_MIN_PASSWORD} characters")
    if pw.lower() in ("password", "12345678", "contrasena", "contraseña", "lucera123",
                      "qwertyui", "11111111", "abcd1234"):
        raise HTTPException(422, "That password is too common. Choose another one.")


def _temp_password() -> str:
    """Contraseña temporal legible por teléfono: sin caracteres que se confundan
    (0/O, 1/l/I) para que se pueda dictar sin errores."""
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnpqrstuvwxyz"
    return "".join(secrets.choice(alfabeto) for _ in range(12))


def _count_active_super_admins(exclude_uid: str | None = None) -> int:
    sql = ("SELECT COUNT(*) c FROM users WHERE role='super_admin' AND deleted_at IS NULL "
           "AND status='active' AND dashboard_access=1")
    args: tuple = ()
    if exclude_uid:
        sql += " AND id<>%s"
        args = (exclude_uid,)
    return int(_q(sql, args)[0]["c"] or 0)


def _guard_last_super_admin(uid: str, role: str) -> None:
    """Impide dejar el tablero sin ningún superadministrador activo. Si eso pasara,
    nadie podría volver a crear usuarios y habría que arreglarlo por SQL a mano."""
    if role == "super_admin" and _count_active_super_admins(exclude_uid=uid) == 0:
        raise HTTPException(
            409, "This is the last active super_admin. Assign another one before removing or "
                 "downgrading this user."
        )


@app.get("/api/roles", dependencies=[Depends(require_auth)])
def roles_catalog():
    """Catálogo de roles internos asignables, con su etiqueta y el rol de tablero al que mapea.

    Sirve para llenar el desplegable de la pestaña Cuentas sin hardcodear la lista.
    `guardian` NO aparece: los acudientes se crean por el registro del bot, no por aquí.
    """
    return {"items": [
        {"value": r, "label": _ROLE_LABELS.get(r, r), "dashboardRole": ROLE_TO_DASHBOARD.get(r)}
        for r in _INTERNAL_ROLES
    ]}


def _user_row(r: dict) -> dict:
    return {
        "id": r["id"], "name": r.get("full_name"), "email": r["email"],
        "phone": r.get("phone_number"), "role": r["role"],
        "dashboardRole": ROLE_TO_DASHBOARD.get(r["role"], "Guardian"),
        "status": r["status"], "isActive": bool(r.get("is_active")),
        "dashboardAccess": bool(r.get("dashboard_access")),
        "hasPassword": bool(r.get("password_hash")),
        # true tras un restablecimiento: el front DEBE forzar el cambio al entrar.
        "mustChangePassword": bool(r.get("must_change_password")),
        "licenseId": r.get("license_id"), "specialty": r.get("medical_specialty"),
        "createdAt": _clean(r.get("created_at")),
    }


def _one_user(uid: str) -> dict:
    rows = _q(
        """SELECT u.*, ud.full_name AS doc_name, ud.license_id, ud.medical_specialty
           FROM users u LEFT JOIN users_doctor ud ON ud.user_id=u.id
           WHERE u.id=%s AND u.deleted_at IS NULL""",
        (uid,),
    )
    if not rows:
        raise HTTPException(404, "user not found")
    return _user_row(rows[0])


class UserCreate(BaseModel):
    name: str
    email: str
    role: str                       # ver _INTERNAL_ROLES
    password: str | None = None     # si no se manda, queda sin clave (no puede entrar)
    phone: str | None = None        # opcional; si falta se usa un marcador interno
    dashboardAccess: bool = True
    licenseId: str | None = None    # solo para doctores
    specialty: str | None = None


class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    role: str | None = None
    status: str | None = None       # active | suspended | inactive
    dashboardAccess: bool | None = None
    licenseId: str | None = None
    specialty: str | None = None


class UserPassword(BaseModel):
    password: str


class UserOwnPassword(BaseModel):
    currentPassword: str
    newPassword: str


@app.post("/api/users", dependencies=[Depends(require_auth)], status_code=201)
def user_create(body: UserCreate):
    """Crea un usuario interno (no acudiente) del tablero."""
    if body.role not in _INTERNAL_ROLES:
        raise HTTPException(422, f"role must be one of: {', '.join(_INTERNAL_ROLES)}")
    email = body.email.lower().strip()
    if _q("SELECT id FROM users WHERE email=%s AND deleted_at IS NULL", (email,)):
        raise HTTPException(409, "email already exists")
    if body.password:
        _check_password_strength(body.password)
    if body.phone and _q("SELECT id FROM users WHERE phone_number=%s AND deleted_at IS NULL",
                         (_digits(body.phone),)):
        raise HTTPException(409, "phone already exists")
    uid = str(uuid.uuid4())
    _exec(
        """INSERT INTO users (id, email, phone_number, password_hash, full_name, role,
                              status, is_active, dashboard_access, free_sessions_used,
                              created_at, updated_at)
           VALUES (%s,%s,%s,%s,%s,%s,'active',1,%s,0,NOW(),NOW())""",
        (uid, email, _digits(body.phone) if body.phone else f"dash-{uid[:12]}",
         _hash_password(body.password) if body.password else "",
         body.name.strip(), body.role, 1 if body.dashboardAccess else 0),
    )
    if body.role == "doctor":
        _exec(
            "INSERT INTO users_doctor (user_id, full_name, license_id, medical_specialty, created_at) "
            "VALUES (%s,%s,%s,%s,NOW())",
            (uid, body.name.strip(), body.licenseId or "", body.specialty),
        )
    return _one_user(uid)


# Las rutas /api/users/me van ANTES que /api/users/{uid}: FastAPI empareja en orden de
# declaracion, y si {uid} va primero se traga "me" como si fuera un id y responde 404.
@app.get("/api/users/me", dependencies=[Depends(require_auth)])
def user_me(claims: dict = Depends(require_auth)):
    """Quién soy, según el token. El front lo usa para saber a quién NO debe dejar borrarse
    y para leer `mustChangePassword` al entrar."""
    uid = claims.get("uid")
    if not uid:
        # Token de X-API-Key: no representa a una persona.
        raise HTTPException(400, "This token is not tied to a user (X-API-Key has no identity).")
    return _one_user(uid)


@app.post("/api/users/me/password", dependencies=[Depends(require_auth)])
def user_change_own_password(body: UserOwnPassword, claims: dict = Depends(require_auth)):
    """Cambio de la PROPIA contraseña, verificando la actual.

    Es el endpoint que cierra el ciclo del restablecimiento: el usuario entra con la temporal
    y cambia aquí. No requiere ser admin — y a propósito NO permite cambiar la de otro.
    """
    uid = claims.get("uid")
    if not uid:
        raise HTTPException(400, "This token is not tied to a user (X-API-Key has no identity).")
    rows = _q("SELECT password_hash FROM users WHERE id=%s AND deleted_at IS NULL", (uid,))
    if not rows:
        raise HTTPException(404, "user not found")
    if not _verify_password(body.currentPassword or "", rows[0]["password_hash"]):
        raise HTTPException(401, "Current password is incorrect.")
    _check_password_strength(body.newPassword or "")
    if body.newPassword == body.currentPassword:
        raise HTTPException(422, "The new password must be different from the current one.")
    _exec("UPDATE users SET password_hash=%s, must_change_password=0, updated_at=NOW() "
          "WHERE id=%s", (_hash_password(body.newPassword), uid))
    return {"ok": True, "mustChangePassword": False}


@app.get("/api/users/{uid}", dependencies=[Depends(require_auth)])
def user_get(uid: str):
    return _one_user(uid)


@app.patch("/api/users/{uid}", dependencies=[Depends(require_auth)])
def user_update(uid: str, body: UserUpdate, claims: dict = Depends(require_auth)):
    actual = _q("SELECT id, role FROM users WHERE id=%s AND deleted_at IS NULL", (uid,))
    if not actual:
        raise HTTPException(404, "user not found")
    rol_actual = actual[0]["role"]
    soy_yo = claims.get("uid") == uid
    # Quitarle el super_admin al ultimo, suspenderlo o dejarlo sin tablero deja el sistema
    # sin quien administre. Mismo motivo que en el borrado.
    if (body.role is not None and body.role != rol_actual) \
       or (body.status is not None and body.status != "active") \
       or body.dashboardAccess is False:
        _guard_last_super_admin(uid, rol_actual)
    if soy_yo and body.dashboardAccess is False:
        raise HTTPException(409, "You cannot remove your own dashboard access.")
    if soy_yo and body.status is not None and body.status != "active":
        raise HTTPException(409, "You cannot deactivate your own user.")
    sets, args = [], []
    if body.name is not None:
        sets.append("full_name=%s"); args.append(body.name.strip())
    if body.email is not None:
        email = body.email.lower().strip()
        if _q("SELECT id FROM users WHERE email=%s AND id<>%s AND deleted_at IS NULL", (email, uid)):
            raise HTTPException(409, "email already exists")
        sets.append("email=%s"); args.append(email)
    if body.role is not None:
        if body.role not in _INTERNAL_ROLES:
            raise HTTPException(422, f"role must be one of: {', '.join(_INTERNAL_ROLES)}")
        sets.append("role=%s"); args.append(body.role)
    if body.status is not None:
        if body.status not in ("active", "suspended", "inactive"):
            raise HTTPException(422, "status must be: active|suspended|inactive")
        sets.append("status=%s"); args.append(body.status)
        sets.append("is_active=%s"); args.append(1 if body.status == "active" else 0)
    if body.dashboardAccess is not None:
        sets.append("dashboard_access=%s"); args.append(1 if body.dashboardAccess else 0)
    if sets:
        _exec(f"UPDATE users SET {', '.join(sets)}, updated_at=NOW() WHERE id=%s", tuple(args + [uid]))
    if body.licenseId is not None or body.specialty is not None or body.name is not None:
        if _q("SELECT user_id FROM users_doctor WHERE user_id=%s", (uid,)):
            ds, da = [], []
            if body.name is not None:
                ds.append("full_name=%s"); da.append(body.name.strip())
            if body.licenseId is not None:
                ds.append("license_id=%s"); da.append(body.licenseId)
            if body.specialty is not None:
                ds.append("medical_specialty=%s"); da.append(body.specialty)
            if ds:
                _exec(f"UPDATE users_doctor SET {', '.join(ds)} WHERE user_id=%s", tuple(da + [uid]))
    return _one_user(uid)


@app.post("/api/users/{uid}/password", dependencies=[Depends(require_auth)])
def user_set_password(uid: str, body: UserPassword):
    """Fija la contraseña del usuario (la elige el admin). Siempre la guarda con PBKDF2,
    así que de paso reemplaza los hashes SHA-256 heredados de METRICS_USERS.

    Limpia `must_change_password`: si un admin le pone una clave definitiva, ya no hay
    nada que forzar.
    """
    if not _q("SELECT id FROM users WHERE id=%s AND deleted_at IS NULL", (uid,)):
        raise HTTPException(404, "user not found")
    _check_password_strength(body.password or "")
    _exec("UPDATE users SET password_hash=%s, must_change_password=0, updated_at=NOW() "
          "WHERE id=%s", (_hash_password(body.password), uid))
    return {"ok": True, "id": uid, "mustChangePassword": False}


@app.post("/api/users/{uid}/password/reset", dependencies=[Depends(require_auth)])
def user_reset_password(uid: str):
    """RESTABLECE la clave: el API genera una temporal, la devuelve **una sola vez** y marca
    la cuenta para que el front obligue a cambiarla al entrar.

    Existe para que un admin no tenga que inventarse una contraseña (y casi siempre elegir
    una débil). La respuesta es lo único que verá: no se guarda en claro en ningún lado.
    """
    rows = _q("SELECT id, email, full_name FROM users WHERE id=%s AND deleted_at IS NULL", (uid,))
    if not rows:
        raise HTTPException(404, "user not found")
    temp = _temp_password()
    _exec("UPDATE users SET password_hash=%s, must_change_password=1, updated_at=NOW() "
          "WHERE id=%s", (_hash_password(temp), uid))
    return {
        "ok": True, "id": uid, "email": rows[0]["email"],
        "temporaryPassword": temp,          # ← única vez que se ve; no se puede recuperar
        "mustChangePassword": True,
    }


@app.delete("/api/users/{uid}", dependencies=[Depends(require_auth)])
def user_delete(uid: str, claims: dict = Depends(require_auth)):
    """Borrado suave: desactiva y le quita el acceso al tablero. Conserva la trazabilidad
    (p. ej. las sesiones que ese médico auditó siguen apuntando a él).

    Dos salvaguardas, porque las dos dejan el sistema inutilizable y no tienen deshacer
    desde la interfaz: no puedes borrarte a ti mismo, ni borrar al último super_admin.
    """
    rows = _q("SELECT id, role FROM users WHERE id=%s AND deleted_at IS NULL", (uid,))
    if not rows:
        raise HTTPException(404, "user not found")
    if claims.get("uid") == uid:
        raise HTTPException(409, "You cannot delete your own user.")
    _guard_last_super_admin(uid, rows[0]["role"])
    _exec("UPDATE users SET deleted_at=NOW(), is_active=0, status='inactive', "
          "dashboard_access=0, updated_at=NOW() WHERE id=%s", (uid,))
    return {"deleted": True, "id": uid}


# ── Historia clínica en PDF ──────────────────────────────────────────────────
#
# Compila TODAS las interacciones de un paciente en un solo documento: identificación,
# antecedentes, y por cada consulta su fecha, la conducta recomendada (casa/cita/urgencias),
# el motivo, la orientación entregada, las banderas clínicas detectadas y la nota del médico
# auditor.
#
# Nota sobre el "resumen": `chat_sessions.summary` todavía no lo escribe nadie (queda
# pendiente que el bot lo genere al cerrar). Mientras tanto el documento usa datos REALES en
# vez de dejar el bloque vacío: el motivo se toma del primer mensaje del acudiente y la
# orientación del último mensaje del bot. Cuando exista `summary`, reemplaza a ambos.
_FLAG_ES = {
    "dificultad_respiratoria": "Dificultad respiratoria",
    "fiebre_alta": "Fiebre alta",
    "convulsion": "Convulsión",
    "deshidratacion": "Deshidratación",
    "sangrado": "Sangrado",
    "letargo": "Letargo / decaimiento",
}
_CONDUCTA = {
    "general": ("Manejo en casa", colors.HexColor("#2E7D5B")),
    "urgente": ("Consulta médica", colors.HexColor("#B5761F")),
    "emergencia": ("Urgencias", colors.HexColor("#B3402F")),
}
_WINE = colors.HexColor("#6B1E33")
_INK = colors.HexColor("#2B1B21")
_MUTED = colors.HexColor("#8B7A80")
_LINE = colors.HexColor("#E7DCD6")
# El documento es clínico y en español: el parentesco no puede salir en inglés como en el API.
_REL_ES = {"madre": "Madre", "padre": "Padre", "tutor": "Tutor/a", "abuelo": "Abuelo/a", "otro": "Otro"}

_SALUDOS = {"hola", "holaa", "holaaa", "buenas", "buenos", "dias", "días", "tardes", "noches",
            "hey", "saludos", "que", "tal", "buen", "dia", "día"}


def _motivo(msgs: list[str]) -> str:
    """Primer mensaje del acudiente que REALMENTE dice algo.

    El primero suele ser un saludo suelto ("Buenos días!", "Holaaaaaa"), que como motivo de
    consulta no informa nada. Se salta lo que sea solo saludo y se toma el primero con
    contenido; si no hay ninguno, se devuelve el primero tal cual.
    """
    for m in msgs:
        limpio = re.sub(r"[^\wáéíóúñ ]+", " ", (m or "").lower())
        palabras = [w for w in limpio.split() if w]
        if len(palabras) > 3 and not all(w in _SALUDOS for w in palabras):
            return m
    return msgs[0] if msgs else ""


def _clinical_history_data(pid: str) -> dict:
    """Reúne todo lo que va en la historia clínica de un paciente."""
    pat = _q(
        """SELECT d.*, g.id AS gid, g.full_name AS guardian, g.account_code, g.address,
                  g.country, g.province, g.city, g.relationship_type,
                  u.phone_number, ic.name AS insurance, d.policy_number
           FROM dependents d
           JOIN guardian_dependent gd ON gd.dependent_id = d.id
           JOIN guardians g ON g.id = gd.guardian_id
           JOIN users u ON u.id = g.user_id
           LEFT JOIN insurance_companies ic
                  ON ic.id = COALESCE(d.insurance_company_id, g.insurance_company_id)
           WHERE d.id = %s LIMIT 1""",
        (pid,),
    )
    if not pat:
        raise HTTPException(404, "patient not found")

    sessions = _q(
        """SELECT cs.id, cs.opened_at, cs.closed_at, cs.summary, cs.doctor_note,
                  cs.reviewed_at, cs.tech_failure, cl.name AS cls,
                  ru.full_name AS reviewer
           FROM chat_sessions cs
           LEFT JOIN classification cl ON cl.id = cs.classification_id
           LEFT JOIN users ru ON ru.id = cs.reviewed_by
           WHERE cs.dependent_id = %s
           ORDER BY cs.opened_at""",
        (pid,),
    )
    ids = [s["id"] for s in sessions]
    user_msgs, last_bot, flags = {}, {}, {}
    if ids:
        ph = ",".join(["%s"] * len(ids))
        for m in _q(
            f"""SELECT session_id, sender_role, content, created_at FROM messages
                WHERE session_id IN ({ph}) ORDER BY created_at""",
            tuple(ids),
        ):
            sid = m["session_id"]
            if m["sender_role"] in ("user", "guardian"):
                user_msgs.setdefault(sid, []).append(m["content"])
            else:
                last_bot[sid] = m["content"]
        for f in _q(
            f"""SELECT m.session_id, mf.flag_type FROM message_flags mf
                JOIN messages m ON m.id = mf.message_id
                WHERE m.session_id IN ({ph})""",
            tuple(ids),
        ):
            flags.setdefault(f["session_id"], set()).add(f["flag_type"])

    for s in sessions:
        s["motivo"] = _motivo(user_msgs.get(s["id"], [])).strip()
        s["orientacion"] = (last_bot.get(s["id"]) or "").strip()
        s["flags"] = sorted(flags.get(s["id"], []))
    return {"patient": pat[0], "sessions": sessions}


def _hc_styles():
    ss = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold",
                             fontSize=17, textColor=colors.white, alignment=TA_LEFT, spaceAfter=2),
        "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=9,
                              textColor=colors.HexColor("#E8D5DB"), alignment=TA_LEFT),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11,
                             textColor=_WINE, spaceBefore=14, spaceAfter=6),
        "lbl": ParagraphStyle("lbl", fontName="Helvetica", fontSize=7.5,
                              textColor=_MUTED, spaceAfter=1),
        "val": ParagraphStyle("val", fontName="Helvetica-Bold", fontSize=9, textColor=_INK),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=8.5,
                               textColor=_INK, leading=11.5, alignment=TA_JUSTIFY),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=7.5,
                                textColor=_MUTED, leading=10),
    }


def _kv_block(pairs, st, cols_n=3, width=479):
    """Rejilla de etiqueta/valor."""
    cells, w = [], width / cols_n
    for i in range(0, len(pairs), cols_n):
        chunk = pairs[i:i + cols_n] + [("", "")] * (cols_n - len(pairs[i:i + cols_n]))
        cells.append([
            [Paragraph(k.upper(), st["lbl"]), Paragraph(v or "—", st["val"])] if k else ""
            for k, v in chunk
        ])
    t = Table(cells, colWidths=[w] * cols_n)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _build_clinical_pdf(data: dict) -> bytes:
    p, sessions = data["patient"], data["sessions"]
    st = _hc_styles()
    buf = io.BytesIO()
    name = p["full_name"]
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=58, rightMargin=58, topMargin=44, bottomMargin=48,
        title=f"Historia clínica — {name}", author="Lucera",
    )
    W = doc.width
    generated = datetime.now().strftime("%d/%m/%Y %H:%M")
    el = []

    # ── Encabezado ──
    head = Table([[
        [Paragraph("Historia clínica", st["h1"]),
         Paragraph("Lucera · Orientación pediátrica", st["sub"])],
        [Paragraph(f'<para align="right">{name}</para>',
                   ParagraphStyle("pn", fontName="Helvetica-Bold", fontSize=11, textColor=colors.white)),
         Paragraph(f'<para align="right">Generada el {generated}</para>', st["sub"])],
    ]], colWidths=[W * 0.58, W * 0.42])
    head.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _WINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 16), ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING", (0, 0), (-1, -1), 13), ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
    ]))
    el += [head, Spacer(1, 16)]

    # ── Identificación ──
    el.append(Paragraph("Identificación del paciente", st["h2"]))
    el.append(_kv_block([
        ("Nombre", name),
        ("Fecha de nacimiento", _clean(p["birthday"]) or "—"),
        ("Edad", f"{_age(p['birthday'])} años"),
        ("Documento", p.get("id_number") or "—"),
        ("Peso registrado", f"{p['weight_kg']} kg" if p.get("weight_kg") is not None else "—"),
        ("Tipo de sangre", BLOOD_OUT.get(p.get("blood_type")) or "—"),
        ("Centro educativo", p.get("school") or "—"),
        ("Seguro", p.get("insurance") or "—"),
        ("Póliza", p.get("policy_number") or "—"),
    ], st, 3, W))

    # ── Acudiente ──
    el.append(Paragraph("Acudiente responsable", st["h2"]))
    el.append(_kv_block([
        ("Nombre", p.get("guardian") or "—"),
        ("Parentesco", _REL_ES.get(p.get("relationship_type"), "—")),
        ("Teléfono", p.get("phone_number") or "—"),
        ("Cuenta", p.get("account_code") or "—"),
        ("Dirección", p.get("address") or "—"),
        ("Ciudad / Provincia", " · ".join(x for x in (p.get("city"), p.get("province")) if x) or "—"),
    ], st, 3, W))

    # ── Antecedentes ──
    el.append(Paragraph("Antecedentes", st["h2"]))
    ante = Table([
        [Paragraph("ALERGIAS", st["lbl"]), Paragraph("CONDICIONES CONOCIDAS", st["lbl"])],
        [Paragraph(p.get("allergies") or "Ninguna referida", st["body"]),
         Paragraph(p.get("known_conditions") or "Ninguna referida", st["body"])],
    ], colWidths=[W / 2, W / 2])
    ante.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FAF6F1")),
        ("BOX", (0, 0), (-1, -1), 0.5, _LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, _LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    el.append(ante)

    # ── Resumen de atenciones ──
    el.append(Paragraph(f"Resumen de atenciones ({len(sessions)})", st["h2"]))
    if not sessions:
        el.append(Paragraph("Este paciente aún no registra consultas.", st["body"]))
    else:
        rows = [[Paragraph(h, ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=7.5,
                                             textColor=colors.white))
                 for h in ("FECHA", "CONDUCTA RECOMENDADA", "BANDERAS CLÍNICAS", "REVISADA")]]
        for s in sessions:
            label, col = _CONDUCTA.get(s["cls"], ("Sin clasificar", _MUTED))
            rows.append([
                Paragraph(_clean(s["opened_at"]) or "—", st["body"]),
                Paragraph(f'<font color="{col.hexval()}"><b>{label}</b></font>', st["body"]),
                Paragraph(", ".join(_FLAG_ES.get(f, f) for f in s["flags"]) or "—", st["body"]),
                Paragraph("Sí" if s["doctor_note"] else "—", st["body"]),
            ])
        t = Table(rows, colWidths=[W * 0.20, W * 0.24, W * 0.41, W * 0.15], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _WINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, _LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAF6F1")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        el.append(t)

        # ── Detalle cronológico ──
        el.append(Paragraph("Detalle de las consultas", st["h2"]))
        for i, s in enumerate(sessions, 1):
            label, col = _CONDUCTA.get(s["cls"], ("Sin clasificar", _MUTED))
            bloque = [
                Table([[
                    Paragraph(f'<b>Consulta {i}</b> · {_clean(s["opened_at"]) or ""}',
                              ParagraphStyle("ch", fontName="Helvetica", fontSize=9, textColor=_INK)),
                    Paragraph(f'<para align="right"><font color="{col.hexval()}"><b>{label}</b></font></para>',
                              ParagraphStyle("cc", fontName="Helvetica", fontSize=9)),
                ]], colWidths=[W * 0.6, W * 0.4]),
            ]
            if s["flags"]:
                bloque.append(Paragraph(
                    "<b>Banderas clínicas:</b> " + ", ".join(_FLAG_ES.get(f, f) for f in s["flags"]),
                    st["body"]))
            if s["summary"]:
                bloque.append(Paragraph(f"<b>Resumen:</b> {s['summary']}", st["body"]))
            else:
                if s["motivo"]:
                    bloque.append(Paragraph(f"<b>Motivo referido:</b> {_trim(s['motivo'], 900)}", st["body"]))
                if s["orientacion"]:
                    bloque.append(Paragraph(f"<b>Orientación entregada:</b> {_trim(s['orientacion'], 1400)}", st["body"]))
            if s["doctor_note"]:
                nota = Table([[Paragraph(
                    f"<b>Nota del médico auditor</b>"
                    f"{(' · ' + s['reviewer']) if s['reviewer'] else ''}"
                    f"{(' · ' + (_clean(s['reviewed_at']) or '')) if s['reviewed_at'] else ''}<br/>"
                    f"{s['doctor_note']}", st["body"])]], colWidths=[W])
                nota.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F2ECE8")),
                    ("LINEBEFORE", (0, 0), (0, -1), 2, _WINE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]))
                bloque.append(nota)
            if s["tech_failure"]:
                bloque.append(Paragraph(
                    "Esta consulta tuvo una interrupción técnica: alguna respuesta no pudo entregarse.",
                    st["small"]))
            el.append(KeepTogether([Spacer(1, 9)] + bloque))

    def _chrome(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(_MUTED)
        canvas.drawString(58, 30,
                          "Documento generado automáticamente por Lucera. Contiene orientación "
                          "pediátrica, NO constituye diagnóstico ni prescripción médica.")
        canvas.drawRightString(A4[0] - 58, 30, f"Página {doc_.page}")
        canvas.setStrokeColor(_LINE)
        canvas.line(58, 40, A4[0] - 58, 40)
        canvas.restoreState()

    doc.build(el, onFirstPage=_chrome, onLaterPages=_chrome)
    return buf.getvalue()


def _trim(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[:n].rsplit(" ", 1)[0] + "…"


@app.get("/api/patients/{pid}/clinical-history", dependencies=[Depends(require_auth)])
def clinical_history(pid: str, download: bool = False):
    """Historia clínica del paciente en PDF: identificación, antecedentes y el compilado
    de todas sus consultas con conducta, banderas y notas del médico auditor."""
    data = _clinical_history_data(pid)
    pdf = _build_clinical_pdf(data)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", data["patient"]["full_name"]).strip("-").lower()
    disp = "attachment" if download else "inline"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'{disp}; filename="historia-clinica-{slug}.pdf"'},
    )


class DoctorNote(BaseModel):
    note: str
    reviewed_by: str | None = None


@app.patch("/api/chats/{sid}/note", dependencies=[Depends(require_auth)])
def chat_note(sid: str, body: DoctorNote):
    """Comentario del médico auditor sobre una sesión (guarda quién y cuándo revisó)."""
    if not _q("SELECT id FROM chat_sessions WHERE id=%s", (sid,)):
        raise HTTPException(404, "session not found")
    _exec("UPDATE chat_sessions SET doctor_note=%s, reviewed_by=%s, reviewed_at=NOW() WHERE id=%s",
          (body.note, body.reviewed_by, sid))
    r = _q("SELECT id, doctor_note, reviewed_by, reviewed_at FROM chat_sessions WHERE id=%s", (sid,))[0]
    return {"id": r["id"], "note": r["doctor_note"], "reviewedBy": r["reviewed_by"],
            "reviewedAt": _clean(r["reviewed_at"])}


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
