#!/bin/bash
# =============================================================================
# 服务器清理脚本
# 用于清理之前的Docker容器、镜像和占用资源
# =============================================================================

echo "=== 开始清理服务器 ==="

# 1. 停止所有运行中的容器
echo "[1/6] 停止所有容器..."
docker stop $(docker ps -aq) 2>/dev/null
echo "✓ 容器已停止"

# 2. 删除所有容器（包括已停止的）
echo "[2/6] 删除所有容器..."
docker rm $(docker ps -aq) 2>/dev/null
echo "✓ 容器已删除"

# 3. 删除所有镜像（可选，如果需要重新构建）
echo "[3/6] 删除所有镜像..."
read -p "是否删除所有镜像？(y/N): " confirm
if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    docker rmi $(docker images -q) -f 2>/dev/null
    echo "✓ 镜像已删除"
else
    echo "⊗ 跳过镜像删除"
fi

# 4. 清理悬空镜像和构建缓存
echo "[4/6] 清理悬空资源..."
docker system prune -f
echo "✓ 悬空资源已清理"

# 5. 清理卷（注意：可能包含数据）
echo "[5/6] 清理未使用的卷..."
read -p "是否删除未使用的卷？(y/N): " confirm
if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    docker volume prune -f
    echo "✓ 卷已清理"
else
    echo "⊗ 跳过卷清理"
fi

# 6. 显示当前状态
echo "[6/6] 当前Docker状态:"
echo "--- 容器 ---"
docker ps -a
echo ""
echo "--- 镜像 ---"
docker images
echo ""
echo "--- 磁盘使用 ---"
docker system df

echo ""
echo "=== 清理完成 ==="