# lucera-metrics

API de métricas (solo lectura) que alimenta el **dashboard del cliente** (repo de Mauro:
`MauricioSantos12/lucera-dashboard`). Lee la BD de Aiven y devuelve los datos en la
**forma exacta** que espera el dashboard (ver `src/lib/mockData.ts`).

## Auth
Todas las rutas `/api/*` requieren el header **`X-API-Key: <METRICS_API_KEY>`**.
`/health` es público.

## Endpoints

| Método · Ruta | Devuelve (tipo del dashboard) | Fuente |
|---|---|---|
| `GET /health` | `{ok:true}` | — |
| `GET /api/acudientes` | `Acudiente[]` (con `ninos: NinoPaciente[]`) | guardians+users+dependents |
| `GET /api/pacientes` | `Paciente[]` | dependents+sesiones |
| `GET /api/chats` | `ChatSesion[]` (con `mensajes[]`) | chat_sessions+messages+flags+classification |
| `GET /api/pagos` | `Pago[]` | payments |
| `GET /api/centros` | `Centro[]` | hospitals |
| `GET /api/seguros` | `{id,nombre}[]` | insurance_companies |
| `GET /api/especialidades` | `string[]` | specialties |
| `GET /api/stats/kpis` | objeto `kpisGenerales` | agregados |
| `GET /api/stats/sesiones-por-mes` | `{mes,sesiones,premium}[]` | chat_sessions+payments |
| `GET /api/stats/triaje` | `{nivel,value,color}[]` | classification |
| `GET /api/stats/planes` | `{plan,usuarios,color}[]` | users+payments |
| `GET /api/stats/tipo-atencion` | `{tipo,value}[]` | chat_sessions |
| `GET /api/stats/csat` | `{semana,csat}[]` | feedback_score |

### Secciones aún sin datos (devuelven `[]`)
`/api/medicos`, `/api/especialistas`, `/api/medicamentos`, `/api/disponibilidad`,
`/api/citas`, `/api/logs` — corresponden a funcionalidades que el producto todavía no
tiene (médicos onboarded, catálogo de meds, agenda, auditoría). Se irán llenando en
fases siguientes; el contrato ya está listo para cuando existan.

## Variables de entorno
`MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DB`, `MYSQL_SSL=true`,
`METRICS_API_KEY` (si está vacía, no exige key — solo para local). Ver `.env.example`.

## Local
```bash
cp .env.example .env   # y rellena
./run.sh               # http://localhost:8099
```

## Deploy (Cloud Run)
Imagen liviana (FastAPI + pymysql). Desplegar con `--no-allow-unauthenticated` no aplica
(el dashboard la consume desde el navegador con la API key); usar **API key** como control.
```bash
gcloud run deploy lucera-metrics --source . --region us-central1 \
  --allow-unauthenticated --env-vars-file cloudrun.env.yaml
```
> El dashboard de Mauro apunta su `VITE_API_URL` (o equivalente) a la URL de este servicio
> y manda `X-API-Key` en cada request.
