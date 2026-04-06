#!/bin/bash
# =============================================================================
# CTF-Agent Docker 启动脚本
# =============================================================================

set -e

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║        CTF-Agent Launcher             ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# 检查 .env 文件
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo -e "${YELLOW}[WARN] .env not found. Creating from .env.example...${NC}"
        cp .env.example .env
        echo -e "${YELLOW}[WARN] Please edit .env with your API keys${NC}"
    else
        echo -e "${RED}[ERROR] .env file not found${NC}"
        exit 1
    fi
fi

# 检查关键环境变量
source .env 2>/dev/null || true

if [ -z "$LLM_API_KEY" ] || [ "$LLM_API_KEY" = "your_api_key_here" ]; then
    echo -e "${RED}[ERROR] LLM_API_KEY not set in .env${NC}"
    exit 1
fi

# 构建镜像
echo -e "${GREEN}[1/2] Building Docker image...${NC}"
docker compose build

# 启动
MODE="${1:-competition}"

case "$MODE" in
    competition|comp|c)
        echo -e "${GREEN}[2/2] Starting Competition Auto-Solve Mode...${NC}"
        docker compose up
        ;;
    interactive|int|i)
        echo -e "${GREEN}[2/2] Starting Interactive Mode...${NC}"
        docker compose run --rm ctf-agent python3 -m app.cli --interactive
        ;;
    *)
        # 当作目标 URL
        echo -e "${GREEN}[2/2] Starting Single Target: $MODE${NC}"
        docker compose run --rm ctf-agent python3 -m app.cli "$MODE"
        ;;
esac
