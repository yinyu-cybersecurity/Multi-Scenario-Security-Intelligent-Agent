#!/bin/bash
# 下载前端静态资源到本地
# 运行此脚本后，Web界面将从本地加载资源，无需访问外部CDN

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STATIC_DIR="$SCRIPT_DIR/web/static"

mkdir -p "$STATIC_DIR/js" "$STATIC_DIR/css"

echo "正在下载前端静态资源..."

# Vue 3
curl -fsSL "https://cdn.bootcdn.net/ajax/libs/vue/3.3.4/vue.global.prod.min.js" \
    -o "$STATIC_DIR/js/vue.global.prod.min.js" && echo "✓ Vue 3.3.4"

# Element Plus JS
curl -fsSL "https://cdn.bootcdn.net/ajax/libs/element-plus/2.4.0/index.full.min.js" \
    -o "$STATIC_DIR/js/element-plus.min.js" && echo "✓ Element Plus JS 2.4.0"

# Element Plus CSS
curl -fsSL "https://cdn.bootcdn.net/ajax/libs/element-plus/2.4.0/index.css" \
    -o "$STATIC_DIR/css/element-plus.css" && echo "✓ Element Plus CSS 2.4.0"

# D3.js
curl -fsSL "https://cdn.bootcdn.net/ajax/libs/d3/7.8.5/d3.min.js" \
    -o "$STATIC_DIR/js/d3.min.js" && echo "✓ D3.js 7.8.5"

echo ""
echo "下载完成！静态资源已保存到 web/static/"
echo "请重新构建 Docker 镜像: docker build -t ctf-agent ."