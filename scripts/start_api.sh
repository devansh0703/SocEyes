#!/bin/bash
# Wrapper to start API server with required env vars
export NVIDIA_API_KEY=$(grep '^export NVIDIA_API_KEY=' /home/devansh/.bashrc | cut -d= -f2 | tr -d '"')
export FDA_RESPONSE_DRY_RUN=false
cd /home/devansh/fda
exec python3 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8123
