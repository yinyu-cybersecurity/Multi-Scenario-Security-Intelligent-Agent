#!/bin/bash
# Kali直接运行脚本

set -e

if [ -z "$1" ]; then
    echo "Usage: ./run_kali.sh <target_url> [competition_host] [competition_token]"
    echo ""
    echo "Examples:"
    echo "  ./run_kali.sh http://target.com"
    echo "  ./run_kali.sh http://target.com competition.host.com your-token"
    exit 1
fi

TARGET="$1"
export COMPETITION_SERVER_HOST="${2:-$COMPETITION_SERVER_HOST}"
export COMPETITION_AGENT_TOKEN="${3:-$COMPETITION_AGENT_TOKEN}"

echo "Target: $TARGET"
[ -n "$COMPETITION_SERVER_HOST" ] && echo "Competition: $COMPETITION_SERVER_HOST"

# 创建虚拟环境（避免系统包冲突）
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "Installing dependencies..."
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install httpx mcp litellm pyyaml pydantic colorlog
fi

# 使用虚拟环境运行
"$VENV_DIR/bin/python" -m app.cli "$TARGET"