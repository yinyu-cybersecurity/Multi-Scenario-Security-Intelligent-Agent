#!/bin/bash
# Kali直接运行脚本（非Docker）

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

python3 -m app.cli "$TARGET"