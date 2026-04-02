#!/bin/bash
# CTF-Agent 一键部署脚本
# 用法: sudo ./scripts/deploy.sh

set -e

echo "========================================"
echo "   CTF-Agent 2.0 部署脚本"
echo "========================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    log_error "请使用root权限运行: sudo $0"
    exit 1
fi

# 项目根目录
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

log_info "项目目录: $PROJECT_DIR"

# ========================================
# 1. 系统更新
# ========================================
log_info "[1/9] 更新系统包..."
if command -v apt &> /dev/null; then
    apt update && apt upgrade -y
elif command -v yum &> /dev/null; then
    yum update -y
fi

# ========================================
# 2. 安装基础依赖（智能检测，避免冲突）
# ========================================
log_info "[2/9] 安装基础依赖..."

if command -v apt &> /dev/null; then
    # 【关键】清理 apt 缓存并修复依赖问题
    log_info "清理 apt 缓存并检查依赖..."
    apt clean 2>/dev/null || true
    apt update 2>/dev/null || true
    apt --fix-broken install -y 2>/dev/null || true
    dpkg --configure -a 2>/dev/null || true

    # Ubuntu/Debian 包检测函数
    is_installed() {
        dpkg -l "$1" 2>/dev/null | grep -q "^ii"
    }

    install_if_missing() {
        if ! is_installed "$1"; then
            apt install -y "$1" 2>/dev/null || log_warn "$1 安装失败，继续..."
        else
            log_info "$1 已安装，跳过"
        fi
    }

    # 基础工具（通常无冲突）- 使用 2>/dev/null 屏蔽错误
    for pkg in git curl wget vim ufw python3 python3-pip python3-venv nginx; do
        install_if_missing "$pkg"
    done

    # Node.js 智能安装（Node.js 20+ 已自带 npm）
    if ! is_installed "nodejs"; then
        log_info "安装 Node.js 20.x..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt install -y nodejs 2>/dev/null || log_warn "Node.js 安装失败"
    else
        node_version=$(node --version 2>/dev/null || echo "unknown")
        log_info "Node.js $node_version 已安装，跳过 npm 单独安装"
    fi

    # Docker 检测与安装
    if command -v docker &> /dev/null; then
        log_info "Docker 已安装，跳过 docker.io 安装"
    else
        log_info "安装 Docker..."
        apt install -y docker-ce docker-ce-cli containerd.io 2>/dev/null || {
            log_warn "Docker 官方版安装失败，尝试 docker.io..."
            apt install -y docker.io 2>/dev/null || log_warn "Docker 安装失败，请手动安装"
        }
    fi

    if command -v docker-compose &> /dev/null; then
        log_info "docker-compose 已安装，跳过"
    else
        apt install -y docker-compose 2>/dev/null || log_warn "docker-compose 安装失败"
    fi

elif command -v yum &> /dev/null; then
    # CentOS/Rocky 包检测
    is_installed_rpm() {
        rpm -q "$1" &>/dev/null
    }

    install_if_missing_rpm() {
        if ! is_installed_rpm "$1"; then
            yum install -y "$1"
        else
            log_info "$1 已安装，跳过"
        fi
    }

    for pkg in git curl wget vim firewalld python3 python3-pip nginx; do
        install_if_missing_rpm "$pkg"
    done

    # Node.js
    if ! is_installed_rpm "nodejs"; then
        log_info "安装 Node.js 20.x..."
        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
        yum install -y nodejs
    else
        node_version=$(node --version 2>/dev/null || echo "unknown")
        log_info "Node.js $node_version 已安装"
    fi

    # Docker
    install_if_missing_rpm "docker"
    install_if_missing_rpm "docker-compose"
fi

# ========================================
# 3. 配置防火墙
# ========================================
log_info "[3/9] 配置防火墙..."

if command -v ufw &> /dev/null; then
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    log_info "UFW防火墙已启用"
elif command -v firewall-cmd &> /dev/null; then
    systemctl start firewalld
    systemctl enable firewalld
    firewall-cmd --permanent --add-port=22/tcp
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --reload
    log_info "Firewalld防火墙已启用"
fi

# ========================================
# 4. Python环境
# ========================================
log_info "[4/9] 配置Python环境..."

# 创建虚拟环境
if [ ! -d "$PROJECT_DIR/venv" ]; then
    python3 -m venv "$PROJECT_DIR/venv"
    log_info "Python虚拟环境已创建"
fi

# 安装依赖
source "$PROJECT_DIR/venv/bin/activate"
if [ -f "requirements.txt" ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
    log_info "Python依赖已安装"
else
    log_warn "requirements.txt 不存在，跳过pip安装"
fi

# ========================================
# 5. 前端构建
# ========================================
log_info "[5/9] 构建前端..."

FRONTEND_DIR="$PROJECT_DIR/frontend"
if [ -d "$FRONTEND_DIR" ]; then
    cd "$FRONTEND_DIR"

    # 安装依赖
    if [ -f "package.json" ]; then
        npm install

        # 创建环境变量
        if [ ! -f ".env.production" ]; then
            log_info "创建前端环境变量文件..."
            cat > .env.production <<EOF
# WebSocket URL（根据实际情况修改）
VITE_WS_URL=ws://localhost:8000/ws
EOF
        fi

        # 构建
        npm run build

        # 部署到Nginx目录
        mkdir -p /var/www/ctf-agent
        cp -r dist/* /var/www/ctf-agent/
        chown -R www-data:www-data /var/www/ctf-agent
        chmod -R 755 /var/www/ctf-agent

        log_info "前端构建完成，已部署到 /var/www/ctf-agent"
    else
        log_warn "前端 package.json 不存在，跳过构建"
    fi
    cd "$PROJECT_DIR"
else
    log_warn "前端目录不存在，跳过前端构建"
fi

# ========================================
# 6. 配置文件
# ========================================
log_info "[6/9] 创建配置文件..."

if [ -f "config.yaml.example" ]; then
    if [ ! -f "config.yaml" ]; then
        cp config.yaml.example config.yaml
        log_info "配置文件已创建: config.yaml"
        log_warn "请编辑 config.yaml 填入你的API密钥！"
    else
        log_info "配置文件已存在，跳过创建"
    fi
fi

# ========================================
# 7. Docker镜像构建（优化版）
# ========================================
log_info "[7/9] 构建Docker工具镜像..."

# 启动Docker服务
systemctl start docker
systemctl enable docker

# 配置Docker资源限制（避免构建时卡死）
log_info "配置Docker资源限制..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com"
  ],
  "max-concurrent-downloads": 3,
  "max-concurrent-uploads": 3,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65535,
      "Soft": 65535
    }
  }
}
EOF
systemctl restart docker

# 构建策略：优先构建all-in-one镜像
if [ -f "docker/all-in-one/Dockerfile" ]; then
    log_info "构建综合工具镜像（all-in-one）..."
    # 限制内存和CPU，避免卡死，启用缓存优化
    docker build \
        --memory=4g \
        --memory-swap=4g \
        --cpus=2 \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        -t ctf-tools:latest \
        -f docker/all-in-one/Dockerfile . || log_warn "all-in-one镜像构建失败"
else
    # Fallback: 构建独立镜像（串行，限制资源）
    if [ -d "docker" ]; then
        log_info "构建独立工具镜像（串行，资源限制）..."
        for dockerfile in docker/*/Dockerfile; do
            if [ -f "$dockerfile" ]; then
                dir=$(dirname "$dockerfile")
                name=$(basename "$dir")
                # 跳过base
                if [ "$name" = "base" ]; then
                    continue
                fi
                image_name="ctf-tools-${name}"
                log_info "构建镜像: $image_name"
                docker build \
                    --memory=2g \
                    --cpus=1 \
                    -t "$image_name:latest" \
                    -f "$dockerfile" . || log_warn "镜像构建失败: $image_name"
            fi
        done
    else
        log_warn "Docker目录不存在，跳过镜像构建"
    fi
fi

# ========================================
# 8. Systemd服务
# ========================================
log_info "[8/9] 创建Systemd服务..."

cat > /etc/systemd/system/ctf-agent.service <<EOF
[Unit]
Description=CTF-Agent Backend Service
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin:/usr/bin"
ExecStart=$PROJECT_DIR/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log_info "Systemd服务已创建"

# ========================================
# 9. Nginx配置
# ========================================
log_info "[9/9] 配置Nginx..."

# WebSocket升级配置
cat > /etc/nginx/conf.d/websocket.conf <<'EOF'
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
EOF

# 站点配置
cat > /etc/nginx/sites-available/ctf-agent <<'EOF'
server {
    listen 80;
    server_name _;

    # 前端静态文件
    location / {
        root /var/www/ctf-agent;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # 后端API代理
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket代理
    location /ws {
        proxy_pass http://127.0.0.1:8000/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    # 文件上传限制
    client_max_body_size 50M;
}
EOF

# 启用站点
ln -sf /etc/nginx/sites-available/ctf-agent /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# 测试并重启
nginx -t && systemctl restart nginx
systemctl enable nginx

log_info "Nginx配置完成"

# ========================================
# 完成
# ========================================
echo ""
echo "========================================"
echo -e "${GREEN}   部署完成!${NC}"
echo "========================================"
echo ""
echo "下一步操作:"
echo ""
echo "1. 编辑配置文件填入API密钥:"
echo "   vim $PROJECT_DIR/config.yaml"
echo ""
echo "2. 启动后端服务:"
echo "   systemctl start ctf-agent"
echo "   systemctl status ctf-agent"
echo ""
echo "3. 查看日志:"
echo "   journalctl -u ctf-agent -f"
echo ""
echo "4. 访问前端:"
echo "   http://$(curl -s ifconfig.me 2>/dev/null || echo 'your-server-ip')"
echo ""
echo "5. 配置HTTPS (可选):"
echo "   certbot --nginx -d your-domain.com"
echo ""
echo "========================================"