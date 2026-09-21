# SocEyes — single image, two roles.
#
# Build once:            docker build -t soceyes:latest .
# Server:                docker compose -f docker-compose.multihost.yml up -d
# Sensor (remote host):  see docker-compose.multihost.yml header comments.
#
# The Go agent is built in stage 1; the server image carries both the API
# and /app/bin/soceyes-agent so the same image works as a sensor container.

FROM golang:1.27-alpine AS agent-builder
WORKDIR /src/agent
COPY agent/go.mod agent/go.sum* ./
RUN go mod download 2>/dev/null || true
COPY agent/ .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/soceyes-agent .

FROM python:3.12-slim AS server
WORKDIR /app

# tini for clean signals; no cache to keep the image small
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY agents/ ./agents/
COPY app_shared/ ./app_shared/
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY wazuh-ruleset/ ./wazuh-ruleset/
COPY sigma/ ./sigma/
COPY panther-analysis/ ./panther-analysis/
COPY soceyes.sh ./

# Prebuilt dashboard (frontend/out) if present; built on demand otherwise.
COPY frontend/out/ ./frontend/out/

COPY --from=agent-builder /out/soceyes-agent ./bin/soceyes-agent

ENV SOC_STATE_DIR=/data/state \
    SOC_PORT=8000 \
    PYTHONUNBUFFERED=1
VOLUME ["/data/state"]
EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
