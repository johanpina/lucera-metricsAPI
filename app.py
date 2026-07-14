"""lucera-metrics — API de métricas para el dashboard del cliente (Mauro).

Solo lectura sobre la BD de Aiven. Devuelve los datos en la forma EXACTA que
espera el dashboard (ver src/lib/mockData.ts de su repo). Protegida por API key
(header X-API-Key). Las secciones sin datos aún (médicos, medicamentos, agenda,
auditoría) devuelven arreglos vacíos para no romper la UI.
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

# ── Conexión a Aiven (read-only) ─────────────────────────────────────────────
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

# ── Auth (JWT del dashboard + API key opcional para server-to-server) ────────
JWT_SECRET = os.environ.get("JWT_SECRET", "lucera-metrics-dev-secret-CHANGE-ME")
JWT_TTL = int(os.environ.get("JWT_TTL_HOURS", "12")) * 3600
API_KEY = os.environ.get("METRICS_API_KEY", "")  # opcional (scripts / server-to-server)


def _load_users() -> dict:
    """Usuarios del dashboard. METRICS_USERS (JSON) o cuentas demo por defecto.

    Formato METRICS_USERS: [{"email","nombre","rol","password"}]  (o "pass_sha256").
    """
    raw = os.environ.get("METRICS_USERS", "").strip()
    if raw:
        try:
            return {u["email"].lower(): u for u in json.loads(raw)}
        except Exception:  # noqa: BLE001
            pass
    pwd = os.environ.get("METRICS_DEMO_PASSWORD", "Lucera2026!")
    demo = [
        {"email": "admin@lucera.pa", "nombre": "Admin Técnico", "rol": "Admin", "password": pwd},
        {"email": "ventas@lucera.pa", "nombre": "Ventas", "rol": "Ventas", "password": pwd},
        {"email": "esanchez@lucera.pa", "nombre": "Dra. Elena Sánchez", "rol": "Médico", "password": pwd},
    ]
    return {u["email"].lower(): u for u in demo}


USERS = _load_users()


def _q(sql: str, args: tuple = ()) -> list[dict]:
    conn = pymysql.connect(**DB)
    try:
        with conn.cursor() as cur:
            # Sin args: NO pasar la tupla vacía para que pymysql no intente
            # formatear con % (rompería literales como DATE_FORMAT '%Y-%m-01').
            if args:
                cur.execute(sql, args)
            else:
                cur.execute(sql)
            return cur.fetchall()
    finally:
        conn.close()


def _clean(v):
    if isinstance(v, (datetime,)):
        return v.strftime("%Y-%m-%d %H:%M")
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    return v


def _row(d: dict) -> dict:
    return {k: _clean(v) for k, v in d.items()}


# ── Auth ─────────────────────────────────────────────────────────────────────
def _check_password(user: dict, password: str) -> bool:
    if "pass_sha256" in user:
        import hashlib

        h = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(h, str(user["pass_sha256"]))
    return hmac.compare_digest(str(user.get("password", "")), password)


def require_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Exige JWT válido (Bearer) del dashboard, o la API key (server-to-server)."""
    if API_KEY and x_api_key and hmac.compare_digest(x_api_key, API_KEY):
        return {"sub": "apikey", "rol": "Admin"}
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expirado. Vuelve a iniciar sesión.")
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=401, detail="Token inválido.")
    raise HTTPException(status_code=401, detail="No autenticado (envía Bearer <jwt> o X-API-Key).")


class LoginIn(BaseModel):
    email: str
    password: str


app = FastAPI(title="Lucera Metrics API", version="1.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"]
)


@app.post("/auth/login")
def login(body: LoginIn) -> dict:
    """Login del dashboard. Devuelve un JWT (Bearer) para las rutas /api/*."""
    u = USERS.get((body.email or "").lower().strip())
    if u is None or not _check_password(u, body.password or ""):
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos.")
    now = int(time.time())
    payload = {
        "sub": body.email.lower().strip(),
        "nombre": u["nombre"],
        "rol": u["rol"],
        "iat": now,
        "exp": now + JWT_TTL,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {"email": payload["sub"], "nombre": u["nombre"], "rol": u["rol"]}}

# ── Mapeos hacia el contrato del dashboard ───────────────────────────────────
REL = {"madre": "Madre", "padre": "Padre", "tutor": "Tutor", "abuelo": "Abuelo/a", "otro": "Tutor"}
ESTADO_CUENTA = {"active": "activa", "inactive": "suspendida", "suspended": "suspendida", "deleted": "baja"}
PAGO_ESTADO = {"confirmed": "confirmado", "pending": "pendiente", "failed": "fallido", "refunded": "reembolsado"}
PAGO_METODO = {"tilopay": "Yappy", "yappy": "Yappy", "stripe": "Stripe"}
TRIAGE_COLOR = {
    "general": "hsl(var(--triage-self))",
    "urgente": "hsl(var(--triage-priority))",
    "emergencia": "hsl(var(--triage-emergency))",
}
MSG_ROL = {"user": "acudiente", "guardian": "acudiente", "assistant": "bot", "bot": "bot", "system": "sistema"}


def _pais(phone: str | None) -> str:
    p = (phone or "").lstrip("+")
    if p.startswith("507"):
        return "Panamá"
    if p.startswith("57"):
        return "Colombia"
    return "Panamá"


def _edad_anios(bday) -> int:
    if not bday:
        return 0
    if isinstance(bday, str):
        try:
            bday = date.fromisoformat(bday[:10])
        except ValueError:
            return 0
    today = date.today()
    return today.year - bday.year - ((today.month, today.day) < (bday.month, bday.day))


def _plan_label(cycle: str | None) -> str:
    if cycle == "annual":
        return "Premium Anual"
    if cycle == "monthly":
        return "Premium Mensual"
    return "Gratuito"


# ── Salud ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    try:
        _q("SELECT 1")
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"db: {e}")


# ── Documentación (sirve docs/index.html en la raíz) ─────────────────────────
try:
    _DOCS = (Path(__file__).parent / "docs" / "index.html").read_text(encoding="utf-8")
except Exception:  # noqa: BLE001
    _DOCS = "<h1>Lucera Metrics API</h1><p>Ver <a href='/docs'>/docs</a>.</p>"


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home() -> str:
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Lucera Metrics API</title></head>"
        f"<body>{_DOCS}</body></html>"
    )


# ── Acudientes (guardians + users + hijos) ───────────────────────────────────
@app.get("/api/acudientes", dependencies=[Depends(require_auth)])
def acudientes() -> list[dict]:
    gs = _q(
        """
        SELECT g.id, g.full_name AS nombre, g.relationship_type AS rel, g.city AS ciudad,
               g.province, u.phone_number AS telefono, u.email, u.status AS ustatus, u.created_at,
               (SELECT p.billing_cycle FROM payments p
                 WHERE p.user_id=u.id AND p.status='confirmed'
                 ORDER BY p.confirmed_at DESC LIMIT 1) AS cycle
        FROM guardians g JOIN users u ON u.id=g.user_id
        ORDER BY g.full_name
        """
    )
    deps = _q(
        """
        SELECT gd.guardian_id, d.id, d.full_name AS nombre, d.birthday AS fechaNacimiento,
               d.blood_type AS tipoSangre, d.weight_kg AS pesoKg,
               d.known_conditions, d.allergies
        FROM dependents d JOIN guardian_dependent gd ON gd.dependent_id=d.id
        """
    )
    by_g: dict = {}
    for d in deps:
        by_g.setdefault(d["guardian_id"], []).append(
            {
                "id": d["id"],
                "nombre": d["nombre"],
                "fechaNacimiento": _clean(d["fechaNacimiento"]),
                "tipoSangre": d["tipoSangre"] or None,
                "pesoKg": float(d["pesoKg"]) if d["pesoKg"] is not None else None,
                "condiciones": [d["known_conditions"]] if d["known_conditions"] else [],
                "alergias": [d["allergies"]] if d["allergies"] else [],
            }
        )
    out = []
    for g in gs:
        out.append(
            {
                "id": g["id"],
                "telefono": g["telefono"],
                "email": g["email"],
                "nombre": g["nombre"],
                "relacion": REL.get(g["rel"], "Tutor"),
                "pais": _pais(g["telefono"]),
                "ciudad": g["ciudad"] or g["province"] or "",
                "estado": ESTADO_CUENTA.get(g["ustatus"], "activa"),
                "plan": _plan_label(g["cycle"]),
                "registrado": _clean(g["created_at"]),
                "ninos": by_g.get(g["id"], []),
            }
        )
    return out


# ── Pacientes (niños aplanados) ──────────────────────────────────────────────
@app.get("/api/pacientes", dependencies=[Depends(require_auth)])
def pacientes() -> list[dict]:
    rows = _q(
        """
        SELECT d.id, d.full_name AS nombre, d.birthday, d.css_number AS cedula,
               g.full_name AS tutor, u.phone_number AS telefono, u.status AS ustatus,
               (SELECT MAX(cs.opened_at) FROM chat_sessions cs WHERE cs.dependent_id=d.id) AS ultima
        FROM dependents d
        JOIN guardian_dependent gd ON gd.dependent_id=d.id
        JOIN guardians g ON g.id=gd.guardian_id
        JOIN users u ON u.id=g.user_id
        ORDER BY d.full_name
        """
    )
    est = {"active": "activo", "inactive": "suspendido", "suspended": "suspendido"}
    return [
        {
            "id": r["id"],
            "nombre": r["nombre"],
            "cedula": r["cedula"] or "",
            "edad": _edad_anios(r["birthday"]),
            "tutor": r["tutor"],
            "telefono": r["telefono"],
            "estado": est.get(r["ustatus"], "pendiente"),
            "ultimaConsulta": _clean(r["ultima"]) if r["ultima"] else "",
        }
        for r in rows
    ]


# ── Chats (sesiones + mensajes) ──────────────────────────────────────────────
@app.get("/api/chats", dependencies=[Depends(require_auth)])
def chats() -> list[dict]:
    ses = _q(
        """
        SELECT cs.id, g.full_name AS acudiente, d.full_name AS paciente,
               u.phone_number AS telefono, cl.name AS triaje, cs.appointment_type,
               cs.summary AS resumenIA, cs.feedback_score AS calificacion,
               cs.status, cs.fsm_state, cs.opened_at AS inicio, cs.closed_at AS cierre,
               (SELECT content FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS ultimoMensaje,
               (SELECT created_at FROM messages m WHERE m.session_id=cs.id ORDER BY m.created_at DESC LIMIT 1) AS hora
        FROM chat_sessions cs
        JOIN guardians g ON g.id=cs.guardian_id
        JOIN users u ON u.id=g.user_id
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
        by_s.setdefault(m["session_id"], []).append(
            {
                "rol": MSG_ROL.get(m["sender_role"], "sistema"),
                "texto": m["content"],
                "hora": _clean(m["created_at"]),
                "tipo": (m["content_type"] or "texto"),
                "alertas": (m["flags"].split(",") if m["flags"] else []),
            }
        )

    def _estado(s):
        if s["status"] == "closed":
            return "cerrada"
        if s["fsm_state"] == "awaiting_user":
            return "esperando"
        return "activa"

    out = []
    for s in ses:
        out.append(
            {
                "id": s["id"],
                "acudiente": s["acudiente"],
                "paciente": s["paciente"] or "",
                "telefono": s["telefono"],
                "triaje": s["triaje"] if s["triaje"] in ("general", "urgente", "emergencia") else "general",
                "tipoAtencion": "Presencial" if (s["appointment_type"] or "").lower().startswith("pres") else "Virtual",
                "resumenIA": s["resumenIA"] or None,
                "calificacion": int(s["calificacion"]) if s["calificacion"] is not None else None,
                "ultimoMensaje": (s["ultimoMensaje"] or "")[:200],
                "hora": _clean(s["hora"]) if s["hora"] else "",
                "inicio": _clean(s["inicio"]) if s["inicio"] else "",
                "cierre": _clean(s["cierre"]) if s["cierre"] else None,
                "mensajes": by_s.get(s["id"], []),
                "estado": _estado(s),
            }
        )
    return out


# ── Pagos ────────────────────────────────────────────────────────────────────
@app.get("/api/pagos", dependencies=[Depends(require_auth)])
def pagos() -> list[dict]:
    rows = _q(
        """
        SELECT p.id, p.provider_txn_id, g.full_name AS acudiente, p.amount_usd AS monto,
               p.provider, p.billing_cycle, p.status, p.created_at, p.confirmed_at
        FROM payments p
        JOIN users u ON u.id=p.user_id
        LEFT JOIN guardians g ON g.user_id=u.id
        ORDER BY p.created_at DESC
        """
    )
    return [
        {
            "id": r["provider_txn_id"] or r["id"],
            "acudiente": r["acudiente"] or "",
            "monto": float(r["monto"]) if r["monto"] is not None else 0,
            "metodo": PAGO_METODO.get(r["provider"], "Yappy"),
            "plan": _plan_label(r["billing_cycle"]),
            "estado": PAGO_ESTADO.get(r["status"], "pendiente"),
            "fecha": _clean(r["confirmed_at"] or r["created_at"]),
            "respuestaProveedor": r["status"],
            "tipoPago": "Crédito",
        }
        for r in rows
    ]


# ── Centros de salud (hospitales) ────────────────────────────────────────────
@app.get("/api/centros", dependencies=[Depends(require_auth)])
def centros() -> list[dict]:
    rows = _q(
        "SELECT id, name AS nombre, city AS ciudad, address AS direccion, phone AS telefono, "
        "recommended AS recomendado FROM hospitals WHERE active=1 OR active IS NULL ORDER BY name"
    )
    out = []
    for r in rows:
        nm = (r["nombre"] or "").lower()
        tipo = "Clínica" if "clínic" in nm or "clinic" in nm else ("Urgencias" if "urgenc" in nm else "Hospital")
        out.append(
            {
                "id": r["id"],
                "nombre": r["nombre"],
                "tipo": tipo,
                "ciudad": r["ciudad"] or "",
                "direccion": r["direccion"] or "",
                "telefono": r["telefono"] or "",
                "horarios": "24/7",
                "recomendado": bool(r["recomendado"]),
            }
        )
    return out


# ── Catálogos ────────────────────────────────────────────────────────────────
@app.get("/api/seguros", dependencies=[Depends(require_auth)])
def seguros() -> list[dict]:
    rows = _q("SELECT id, name FROM insurance_companies ORDER BY name")
    return [{"id": r["id"], "nombre": r["name"]} for r in rows]


@app.get("/api/especialidades", dependencies=[Depends(require_auth)])
def especialidades() -> list[str]:
    rows = _q("SELECT name FROM specialties ORDER BY name")
    return [r["name"] for r in rows]


# ── Estadísticas ─────────────────────────────────────────────────────────────
@app.get("/api/stats/kpis", dependencies=[Depends(require_auth)])
def kpis() -> dict:
    ac = _q("SELECT COUNT(*) c FROM users WHERE status='active'")[0]["c"]
    ni = _q("SELECT COUNT(*) c FROM dependents")[0]["c"]
    sm = _q("SELECT COUNT(*) c FROM chat_sessions WHERE opened_at >= DATE_FORMAT(NOW(),'%Y-%m-01')")[0]["c"]
    pagos = _q("SELECT COUNT(DISTINCT user_id) c FROM payments WHERE status='confirmed'")[0]["c"]
    total_u = _q("SELECT COUNT(*) c FROM users")[0]["c"] or 1
    csat_row = _q("SELECT AVG(feedback_score) a, COUNT(feedback_score) n FROM chat_sessions")[0]
    emg = _q("SELECT COUNT(*) c FROM chat_sessions cs JOIN classification cl ON cl.id=cs.classification_id WHERE cl.name='emergencia'")[0]["c"]
    deriv = _q("SELECT COUNT(*) c FROM chat_sessions WHERE hospital_id IS NOT NULL OR appointment_type='presencial'")[0]["c"]
    ing = _q("SELECT COALESCE(SUM(amount_usd),0) s FROM payments WHERE status='confirmed' AND confirmed_at >= DATE_FORMAT(NOW(),'%Y-%m-01')")[0]["s"]
    csat_pct = round(float(csat_row["a"]) / 5 * 100) if csat_row["a"] else 0
    return {
        "acudientesActivos": ac,
        "ninosRegistrados": ni,
        "sesionesMes": sm,
        "conversionPremium": round(pagos / total_u * 100, 1),
        "csat": csat_pct,
        "emergenciasDetectadas": emg,
        "derivacionesPresenciales": deriv,
        "ingresosMes": float(ing),
    }


_MES_ES = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"]


@app.get("/api/stats/sesiones-por-mes", dependencies=[Depends(require_auth)])
def sesiones_por_mes() -> list[dict]:
    rows = _q(
        """
        SELECT YEAR(opened_at) y, MONTH(opened_at) m, COUNT(*) sesiones
        FROM chat_sessions WHERE opened_at IS NOT NULL
        GROUP BY YEAR(opened_at), MONTH(opened_at) ORDER BY y, m
        """
    )
    prem = _q(
        """
        SELECT YEAR(confirmed_at) y, MONTH(confirmed_at) m, COUNT(*) premium
        FROM payments WHERE status='confirmed' AND confirmed_at IS NOT NULL
        GROUP BY YEAR(confirmed_at), MONTH(confirmed_at)
        """
    )
    pmap = {(p["y"], p["m"]): p["premium"] for p in prem}
    return [
        {"mes": _MES_ES[r["m"] - 1], "sesiones": r["sesiones"], "premium": pmap.get((r["y"], r["m"]), 0)}
        for r in rows
    ]


@app.get("/api/stats/triaje", dependencies=[Depends(require_auth)])
def stats_triaje() -> list[dict]:
    rows = _q(
        """
        SELECT cl.name, COUNT(*) value FROM chat_sessions cs
        JOIN classification cl ON cl.id=cs.classification_id GROUP BY cl.name
        """
    )
    order = {"general": 0, "urgente": 1, "emergencia": 2}
    rows.sort(key=lambda r: order.get(r["name"], 9))
    return [
        {"nivel": r["name"].capitalize(), "value": r["value"], "color": TRIAGE_COLOR.get(r["name"], "")}
        for r in rows
    ]


@app.get("/api/stats/planes", dependencies=[Depends(require_auth)])
def stats_planes() -> list[dict]:
    rows = _q(
        """
        SELECT COALESCE(
                 (SELECT p.billing_cycle FROM payments p
                   WHERE p.user_id=u.id AND p.status='confirmed'
                   ORDER BY p.confirmed_at DESC LIMIT 1), 'free') AS cycle,
               COUNT(*) c
        FROM users u GROUP BY cycle
        """
    )
    colors = {"Gratuito": "hsl(var(--triage-self))", "Premium Mensual": "hsl(var(--accent))", "Premium Anual": "hsl(var(--primary))"}
    agg: dict = {}
    for r in rows:
        agg[_plan_label(r["cycle"])] = agg.get(_plan_label(r["cycle"]), 0) + r["c"]
    return [{"plan": k, "usuarios": v, "color": colors.get(k, "")} for k, v in agg.items()]


@app.get("/api/stats/tipo-atencion", dependencies=[Depends(require_auth)])
def stats_tipo_atencion() -> list[dict]:
    pres = _q("SELECT COUNT(*) c FROM chat_sessions WHERE hospital_id IS NOT NULL OR appointment_type='presencial'")[0]["c"]
    tot = _q("SELECT COUNT(*) c FROM chat_sessions")[0]["c"]
    return [
        {"tipo": "Virtual (cerrada en chat)", "value": tot - pres},
        {"tipo": "Derivada a presencial", "value": pres},
    ]


@app.get("/api/stats/csat", dependencies=[Depends(require_auth)])
def stats_csat() -> list[dict]:
    rows = _q(
        """
        SELECT YEARWEEK(closed_at) yw, ROUND(AVG(feedback_score)/5*100) csat
        FROM chat_sessions WHERE feedback_score IS NOT NULL AND closed_at IS NOT NULL
        GROUP BY YEARWEEK(closed_at) ORDER BY yw
        """
    )
    return [{"semana": f"S{i + 1}", "csat": int(r["csat"])} for i, r in enumerate(rows)]


# ── Secciones sin datos aún (funcionalidad futura) → arreglos vacíos ─────────
@app.get("/api/medicos", dependencies=[Depends(require_auth)])
def medicos() -> list[dict]:
    return []


@app.get("/api/especialistas", dependencies=[Depends(require_auth)])
def especialistas() -> list[dict]:
    return []


@app.get("/api/medicamentos", dependencies=[Depends(require_auth)])
def medicamentos() -> list[dict]:
    return []


@app.get("/api/disponibilidad", dependencies=[Depends(require_auth)])
def disponibilidad() -> list[dict]:
    return []


@app.get("/api/citas", dependencies=[Depends(require_auth)])
def citas() -> list[dict]:
    return []


@app.get("/api/logs", dependencies=[Depends(require_auth)])
def logs() -> list[dict]:
    return []
