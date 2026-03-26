#!/bin/bash
echo "============================================"
echo "CTF-Agent Web UI"
echo "============================================"
echo ""

cd "$(dirname "$0")"

echo "Starting web server..."
echo "Access URL: http://localhost:54565/fisher_ctf_agent/monitor"
echo ""

python web/api.py