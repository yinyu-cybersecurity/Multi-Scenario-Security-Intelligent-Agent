#!/bin/bash
# 构建所有Docker工具镜像

set -e

echo "=== 构建CTF工具Docker镜像 ==="

# 镜像列表
IMAGES=(
    "web-tools:ctf-tools-web"
    "pwn-tools:ctf-tools-pwn"
    "ad-tools:ctf-tools-ad"
    "deser-tools:ctf-tools-deser"
    "misc-tools:ctf-tools-misc"
)

# 构建每个镜像
for item in "${IMAGES[@]}"; do
    IFS=':' read -r dir name <<< "$item"
    echo ""
    echo "--- 构建 $name ---"
    docker build -t "${name}:latest" -f "docker/${dir}/Dockerfile" .
done

echo ""
echo "=== 构建完成 ==="
echo "镜像列表:"
docker images | grep ctf-tools