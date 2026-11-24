#!/bin/sh
set -eu
command -v lsof >/dev/null || { echo '请先安装 lsof，以检查端口占用'; exit 1; }

pids=$(lsof -tiTCP:8000 -tiTCP:5173 -sTCP:LISTEN || true)
if [ -z "$pids" ]; then
    echo '端口 8000 和 5173 没有正在监听的进程。'
    exit 0
fi

echo '将停止监听端口 8000 或 5173 的进程（可能包括其他项目）：'
lsof -nP -iTCP:8000 -iTCP:5173 -sTCP:LISTEN || true
failed=0
for pid in $pids; do
    if kill "$pid" 2>/dev/null; then
        echo "已向进程 $pid 发送停止信号。"
    else
        echo "无法停止进程 $pid，请检查权限或进程状态。" >&2
        failed=1
    fi
done
if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo '请稍等片刻后运行 ./start.sh；若仍提示端口被占用，请检查占用进程。'
