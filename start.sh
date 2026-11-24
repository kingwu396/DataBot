#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v uv >/dev/null || { echo '请先安装 uv'; exit 1; }
command -v npm >/dev/null || { echo '请先安装 Node.js 和 npm'; exit 1; }
command -v lsof >/dev/null || { echo '请先安装 lsof，以检查端口占用'; exit 1; }
if lsof -nP -iTCP:8000 -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1; then
    echo '无法启动：端口 8000 或 5173 已被占用。'
    lsof -nP -iTCP:8000 -iTCP:5173 -sTCP:LISTEN || true
    echo '确认这些程序可以关闭后，运行：./stop.sh'
    echo '然后重新运行：./start.sh'
    exit 1
fi
(cd backend && UV_PROJECT_ENVIRONMENT=.venv uv sync --locked)
if [ ! -d frontend/node_modules ]; then (cd frontend && npm ci); fi
cleanup() { kill "$backend_pid" "$frontend_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
(cd backend && UV_PROJECT_ENVIRONMENT=.venv uv run --locked uvicorn main:app --host 127.0.0.1 --port 8000) &
backend_pid=$!
(cd frontend && npm run dev) &
frontend_pid=$!
echo '浏览器访问 http://127.0.0.1:5173，按 Ctrl+C 停止。'
wait
