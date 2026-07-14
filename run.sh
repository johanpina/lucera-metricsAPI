#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ./.env; set +a
exec uv run uvicorn app:app --host 0.0.0.0 --port "${METRICS_PORT:-8099}"
