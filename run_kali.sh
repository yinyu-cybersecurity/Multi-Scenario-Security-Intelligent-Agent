#!/bin/bash
# =============================================================================
# CTF-Agent Kali 直接运行脚本（不使用 Docker）
# =============================================================================

set -e

# 加载 .env
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# 检查 API key
if [ -z "$LLM_API_KEY" ] || [ "$LLM_API_KEY" = "your_api_key_here" ]; then
    echo "[ERROR] LLM_API_KEY not set. Edit .env file."
    exit 1
fi

# 虚拟环境
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[Setup] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install -r requirements.txt
fi

# 启动
MODE="${1:-competition}"

case "$MODE" in
    competition|comp|c)
        echo "[Start] Competition Auto-Solve Mode"
        "$VENV_DIR/bin/python" -m app.cli --competition
        ;;
    repl|r)
        echo "[Start] Smart REPL Mode"
        "$VENV_DIR/bin/python" -m app.cli --repl
        ;;
    interactive|int|i)
        echo "[Start] Interactive Mode"
        "$VENV_DIR/bin/python" -m app.cli --interactive
        ;;
    *)
        echo "[Start] Single Target: $MODE"
        "$VENV_DIR/bin/python" -m app.cli "$MODE"
        ;;
esac
