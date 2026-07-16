# lucera-metrics

API que alimenta el **dashboard del cliente** (repo de Mauro: `MauricioSantos12/lucera-dashboard`).
Lee/escribe la BD de Aiven y devuelve los datos con **campos y rutas en inglés**.
Documentación completa y navegable en `/` (ver `docs/index.html`).

## Auth (JWT · access + refresh)

`POST /auth/login` devuelve **dos tokens**:

- `access_token` — corto (**2 h**), va en `Authorization: Bearer` en cada `/api/*`.
- `refresh_token` — largo (**30 días**), sirve para renovar el access **sin re-login**.

```
POST /auth/login    { email, password }        → { access_token, refresh_token, token_type, expires_in, user }
POST /auth/refresh  { refresh_token }           → { access_token, token_type, expires_in }
GET  /api/*         Authorization: Bearer <access_token>
```

Al caducar el access → `401 Token expired` → llamar `/auth/refresh`. Si el refresh también caducó → re-login.
`/health`, `/auth/login` y `/auth/refresh` son públicos. Alternativa server-to-server: header `X-API-Key`.

**Usuarios:** cuentas demo (`admin@lucera.pa`, `ventas@lucera.pa`, `esanchez@lucera.pa`) con la
contraseña de `METRICS_DEMO_PASSWORD`. Para cuentas reales: `METRICS_USERS` (JSON `[{email,name,role,password}]`).

## Paginación

Todas las listas devuelven un **envelope** y aceptan `?page` (def. 1) y `?page_limit` (def. 20, máx. 200):

```json
{ "items": [ /* … */ ], "page": 1, "page_limit": 20, "total": 5, "total_pages": 1 }
```

`/api/guardians` y `/api/patients` aceptan además `?q=` (busca por nombre / teléfono / email).

## Endpoints

| Método · Ruta | Devuelve | Fuente |
|---|---|---|
| `GET /health` | `{ok:true}` | — (público) |
| `POST /auth/login` · `POST /auth/refresh` | tokens | usuarios (env/demo) — público |
| `GET/POST /api/guardians` | envelope `Guardian` (con `insurance{id,name,policyNumber}` + `children[]`) / crea acudiente + user | guardians+users+dependents+insurance |
| `GET/PATCH/DELETE /api/guardians/{id}` | un `Guardian` / actualizado / `{deleted,id}` | — (DELETE = borrado suave) |
| `GET/POST/PATCH/DELETE /api/patients[/{id}]` | CRUD de pacientes (con `insurance`) | dependents+guardian_dependent |
| `GET /api/chats` | envelope `Chat` (con `messages[]`) | chat_sessions+messages+flags |
| `GET/POST /api/payments` · `GET /api/payments/{id}` | envelope `Payment` / registra pago | payments+subscription_plans |
| `GET /api/plans` | envelope de planes de suscripción | subscription_plans |
| `GET/POST/PATCH/DELETE /api/centers[/{id}]` | CRUD de centros de atención | hospitals |
| `GET/POST/PATCH/DELETE /api/insurances[/{id}]` | CRUD de seguros médicos | insurance_companies |
| `GET /api/specialties` · `GET /api/specialties/all` · `POST/PATCH/DELETE` | `string[]` / con ids / CRUD | specialties |
| `GET /api/usage/summary` · `/by-day` · `/by-user` | consumo de tokens/costo LLM | ai_model_runs |
| `GET /api/stats/*` | KPIs y series (cacheados ~60 s) | agregados |

**Campos del acudiente (POST/PATCH):** `name, phone, email, relationship, country, city,
province, status, plan, insuranceId, policyNumber`. Notas: `country` es informativo (el país
se infiere del prefijo del teléfono); `plan` (`free|premium_monthly|premium_annual`) se
materializa como un pago confirmado en `payments`; el seguro (`insuranceId`+`policyNumber`)
se propaga a los pacientes del acudiente (un acudiente sin pacientes aún no lo almacena).

**Cache:** las estadísticas y los consumos se cachean en memoria ~60 s por instancia.

### Secciones aún sin datos (envelope vacío)
`/api/doctors`, `/api/specialists`, `/api/medications`, `/api/availability`, `/api/appointments`,
`/api/logs` — ya paginados, se llenan en fases siguientes.

## Variables de entorno
`MYSQL_HOST/PORT/USER/PASSWORD/DB`, `MYSQL_SSL=true`, `JWT_SECRET`, `ACCESS_TTL_HOURS` (def. 2),
`REFRESH_TTL_DAYS` (def. 30), `METRICS_API_KEY`, `METRICS_DEMO_PASSWORD`, `METRICS_USERS`. Ver `.env.example`.

## Local
```bash
cp .env.example .env   # y rellena
./run.sh
```

## Deploy (Cloud Run)
```bash
gcloud run deploy lucera-metrics --source . --region us-central1 \
  --memory 512Mi --env-vars-file cloudrun.env.yaml
```
El dashboard apunta su `VITE_API_URL` a la URL del servicio y hace login para obtener el `access_token`.
