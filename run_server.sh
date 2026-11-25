#!/usr/bin/env bash
# ==============================================================================
# FootprintIQ - Linux Server Launcher
# Binds to 0.0.0.0:8000 (accessible on host via http://localhost:8000)
# ==============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

echo "======================================================================"
echo " Starting FootprintIQ — OSINT Recon & Vulnerability Platform"
echo " Environment: Kali Linux / Cross-Platform Deployment"
echo " Project Root: $PROJECT_ROOT"
echo "======================================================================"

# 1. Activate Virtual Environment
if [ -d "$PROJECT_ROOT/.venv" ]; then
    source "$PROJECT_ROOT/.venv/bin/activate"
    echo "[✓] Virtual environment activated (.venv)"
else
    echo "[!] Virtual environment .venv not found. Using system python."
fi

# 2. Check SeaweedFS
if pgrep -f "weed server" > /dev/null; then
    echo "[✓] SeaweedFS daemon is running (Ports 9333/8080)"
else
    echo "[i] Starting SeaweedFS server..."
    mkdir -p data/seaweedfs
    nohup weed server -dir="$PROJECT_ROOT/data/seaweedfs" -ip=127.0.0.1 -master.port=9333 -volume.port=8080 -filer=false -s3=false -webdav=false > /tmp/seaweedfs.log 2>&1 &
    sleep 1
    echo "[✓] SeaweedFS launched in background"
fi

# 3. Launch Uvicorn
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
echo "[✓] Launching Uvicorn ASGI server on http://0.0.0.0:8000 (http://localhost:8000)..."
exec uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload --no-server-header

