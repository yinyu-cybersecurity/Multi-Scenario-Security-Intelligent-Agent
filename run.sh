#!/bin/bash
# Docker启动脚本

set -e

# 构建镜像
echo "构建Docker镜像..."
docker build -t ctf-agent:latest .

# 检查参数
if [ -z "$1" ]; then
    echo "Usage: ./run.sh <target_url> [competition_host] [competition_token]"
    echo ""
    echo "Examples:"
    echo "  普通模式:   ./run.sh http://target.com"
    echo "  比赛模式:   ./run.sh http://target.com competition.example.com your-token"
    exit 1
fi

TARGET="$1"
COMP_HOST="${2:-$COMPETITION_SERVER_HOST}"
COMP_TOKEN="${3:-$COMPETITION_AGENT_TOKEN}"

# 运行容器
echo "启动CTF-Agent"
echo "  目标: $TARGET"
[ -n "$COMP_HOST" ] && echo "  比赛平台: $COMP_HOST"

docker run -it --rm \
    -v "$(pwd)/skills:/app/skills" \
    -v "$(pwd)/logs:/app/logs" \
    -e TARGET="$TARGET" \
    -e COMPETITION_SERVER_HOST="$COMP_HOST" \
    -e COMPETITION_AGENT_TOKEN="$COMP_TOKEN" \
    ctf-agent:latest \
    python3 -m app.cli "$TARGET"