# CTF-Agent 服务器部署指南

本指南将教你在Linux服务器上完整部署CTF-Agent 2.0。

---

## 目录

1. [服务器要求](#服务器要求)
2. [环境准备](#环境准备)
3. [安装Docker](#安装docker)
4. [项目部署](#项目部署)
5. [前端构建](#前端构建)
6. [后端配置](#后端配置)
7. [Nginx反向代理](#nginx反向代理)
8. [HTTPS配置](#https配置)
9. [进程管理](#进程管理)
10. [监控与日志](#监控与日志)
11. [常见问题](#常见问题)

---

## 服务器要求

### 最低配置

| 资源 | 要求 |
|------|------|
| CPU | 2核 |
| 内存 | 4GB |
| 存储 | 40GB SSD |
| 带宽 | 5Mbps |

### 推荐配置

| 资源 | 要求 |
|------|------|
| CPU | 4核+ |
| 内存 | 8GB+ |
| 存储 | 100GB SSD |
| 带宽 | 10Mbps+ |

### 支持的系统

- Ubuntu 20.04/22.04 LTS (推荐)
- Debian 11/12
- CentOS 8+
- Rocky Linux 8+

---

## 环境准备

### 1. 更新系统

```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/Rocky
sudo yum update -y
```

### 2. 安装基础工具

```bash
# Ubuntu/Debian
sudo apt install -y git curl wget vim ufw

# CentOS/Rocky
sudo yum install -y git curl wget vim firewalld
```

### 3. 配置防火墙

```bash
# Ubuntu (UFW)
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 8000/tcp    # 后端API（可选，用于调试）
sudo ufw enable

# CentOS (firewalld)
sudo systemctl start firewalld
sudo systemctl enable firewalld
sudo firewall-cmd --permanent --add-port=22/tcp
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

---

## 安装Docker

### 1. 安装Docker Engine

```bash
# 使用官方脚本安装（推荐）
curl -fsSL https://get.docker.com | sh

# 将当前用户加入docker组（免sudo）
sudo usermod -aG docker $USER

# 重新登录或执行
newgrp docker
```

### 2. 验证安装

```bash
docker --version
# Docker version 24.0.x, build xxx

docker run hello-world
# 成功输出 "Hello from Docker!"
```

### 3. 配置Docker镜像加速（国内服务器）

```bash
# 创建配置文件
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<EOF
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com"
  ]
}
EOF

# 重启Docker
sudo systemctl daemon-reload
sudo systemctl restart docker
```

---

## 项目部署

### 1. 克隆项目

```bash
# 创建工作目录
mkdir -p /opt/ctf-agent
cd /opt/ctf-agent

# 克隆代码
git clone https://github.com/yinyu-cybersecurity/Multi-Scenario-Security-Intelligent-Agent.git .
```

### 2. 目录结构

```
/opt/ctf-agent/
├── app/                 # 后端代码
├── frontend/            # 前端代码
├── docker/              # Docker配置
├── config.yaml.example  # 配置模板
└── requirements.txt     # Python依赖
```

### 3. 安装Python环境

```bash
# 安装Python 3.10+
sudo apt install -y python3.10 python3.10-venv python3-pip

# 创建虚拟环境
python3.10 -m venv /opt/ctf-agent/venv
source /opt/ctf-agent/venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

---

## 前端构建

### 1. 安装Node.js

```bash
# 使用nvm安装（推荐）
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc

# 安装Node.js 18+
nvm install 18
nvm use 18

# 验证
node --version  # v18.x.x
npm --version   # 9.x.x
```

### 2. 构建前端

```bash
cd /opt/ctf-agent/frontend

# 安装依赖
npm install

# 创建环境变量文件
cat > .env.production <<EOF
VITE_WS_URL=wss://your-domain.com/ws
EOF

# 构建
npm run build

# 构建产物在 dist/ 目录
ls dist/
# index.html  assets/
```

### 3. 部署前端静态文件

```bash
# 创建Web目录
sudo mkdir -p /var/www/ctf-agent

# 复制构建产物
sudo cp -r dist/* /var/www/ctf-agent/

# 设置权限
sudo chown -R www-data:www-data /var/www/ctf-agent
sudo chmod -R 755 /var/www/ctf-agent
```

---

## 后端配置

### 1. 创建配置文件

```bash
cd /opt/ctf-agent

# 复制模板
cp config.yaml.example config.yaml

# 编辑配置
vim config.yaml
```

### 2. 配置内容

```yaml
# config.yaml
llm:
  default_model: "glm-4-flash"  # 或 "gpt-4", "claude-3-opus"
  api_keys:
    openai: "sk-xxx"            # OpenAI API Key
    anthropic: "sk-xxx"         # Claude API Key
    zhipu: "xxx.xxxx"           # 智谱 API Key

# 工具容器配置
tools:
  docker_enabled: true
  default_timeout: 300
  
# Web界面配置
web:
  host: "0.0.0.0"
  port: 8000
  cors_origins:
    - "https://your-domain.com"
    - "http://localhost:5173"
```

### 3. 构建Docker工具镜像

```bash
cd /opt/ctf-agent

# 构建所有工具镜像
chmod +x scripts/build-images.sh
./scripts/build-images.sh

# 或单独构建
docker build -t ctf-tools-web:latest -f docker/web-tools/Dockerfile .
docker build -t ctf-tools-pwn:latest -f docker/pwn-tools/Dockerfile .
docker build -t ctf-tools-ad:latest -f docker/ad-tools/Dockerfile .
```

### 4. 验证镜像

```bash
docker images | grep ctf-tools
# ctf-tools-web    latest    xxx    800MB
# ctf-tools-pwn    latest    xxx    300MB
# ctf-tools-ad     latest    xxx    400MB
```

---

## Nginx反向代理

### 1. 安装Nginx

```bash
sudo apt install -y nginx
```

### 2. 创建配置文件

```bash
sudo vim /etc/nginx/sites-available/ctf-agent
```

### 3. Nginx配置

```nginx
# /etc/nginx/sites-available/ctf-agent

# WebSocket升级配置
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    server_name your-domain.com;  # 替换为你的域名

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
```

### 4. 启用配置

```bash
# 创建软链接
sudo ln -s /etc/nginx/sites-available/ctf-agent /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重启Nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

---

## HTTPS配置

### 1. 安装Certbot

```bash
sudo apt install -y certbot python3-certbot-nginx
```

### 2. 获取SSL证书

```bash
# 自动配置（推荐）
sudo certbot --nginx -d your-domain.com

# 或手动获取
sudo certbot certonly --nginx -d your-domain.com
```

### 3. 自动续期

```bash
# 测试续期
sudo certbot renew --dry-run

# Certbot会自动添加定时任务
```

### 4. 更新Nginx配置（手动配置HTTPS）

如果Certbot没有自动配置，手动添加：

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # SSL优化
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # ... 其余location配置同上
}

# HTTP重定向到HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 进程管理

### 方式一：Systemd服务（推荐）

#### 1. 创建服务文件

```bash
sudo vim /etc/systemd/system/ctf-agent.service
```

#### 2. 服务配置

```ini
[Unit]
Description=CTF-Agent Backend Service
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ctf-agent
Environment="PATH=/opt/ctf-agent/venv/bin:/usr/bin"
ExecStart=/opt/ctf-agent/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 3. 启动服务

```bash
# 重载配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start ctf-agent

# 开机自启
sudo systemctl enable ctf-agent

# 查看状态
sudo systemctl status ctf-agent
```

### 方式二：Docker Compose

#### 1. 创建docker-compose.yml

```yaml
# /opt/ctf-agent/docker-compose.yml
version: '3.8'

services:
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./data:/app/data
    environment:
      - PYTHONUNBUFFERED=1
    depends_on:
      - redis
    restart: always

  frontend:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./frontend/dist:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - backend
    restart: always

  redis:
    image: redis:alpine
    restart: always
```

#### 2. 启动

```bash
docker-compose up -d
```

---

## 监控与日志

### 1. 日志查看

```bash
# Systemd服务日志
sudo journalctl -u ctf-agent -f

# Nginx访问日志
tail -f /var/log/nginx/access.log

# Nginx错误日志
tail -f /var/log/nginx/error.log
```

### 2. 日志轮转

```bash
# 创建日志配置
sudo vim /etc/logrotate.d/ctf-agent
```

```
/var/log/ctf-agent/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
}
```

### 3. 监控脚本

```bash
# 创建健康检查脚本
vim /opt/ctf-agent/scripts/health-check.sh
```

```bash
#!/bin/bash
# 健康检查脚本

BACKEND_URL="http://localhost:8000/api/health"
ALERT_EMAIL="admin@your-domain.com"

check_backend() {
    response=$(curl -s -o /dev/null -w "%{http_code}" $BACKEND_URL)
    if [ "$response" != "200" ]; then
        echo "CTF-Agent backend is down! HTTP $response"
        # 可以添加邮件通知
        # mail -s "CTF-Agent Alert" $ALERT_EMAIL <<< "Backend is down"
        sudo systemctl restart ctf-agent
    fi
}

check_docker() {
    if ! docker info &> /dev/null; then
        echo "Docker is not running!"
        sudo systemctl restart docker
    fi
}

check_backend
check_docker
```

### 4. Cron定时任务

```bash
# 添加定时检查
crontab -e

# 每5分钟检查一次
*/5 * * * * /opt/ctf-agent/scripts/health-check.sh >> /var/log/ctf-agent/health.log 2>&1
```

---

## 常见问题

### Q1: WebSocket连接失败

```bash
# 检查Nginx配置
sudo nginx -t

# 检查后端服务
sudo systemctl status ctf-agent

# 检查防火墙
sudo ufw status
```

**解决方案**：确保Nginx正确配置WebSocket升级头。

### Q2: Docker镜像拉取失败

```bash
# 检查Docker状态
sudo systemctl status docker

# 检查镜像加速配置
cat /etc/docker/daemon.json

# 重启Docker
sudo systemctl restart docker
```

### Q3: 文件上传失败

```bash
# 检查Nginx配置
grep client_max_body_size /etc/nginx/sites-available/ctf-agent

# 检查目录权限
ls -la /var/www/ctf-agent/uploads/

# 检查磁盘空间
df -h
```

### Q4: API密钥错误

```bash
# 检查配置文件
cat /opt/ctf-agent/config.yaml | grep -A 5 api_keys

# 测试API连接
curl -H "Authorization: Bearer YOUR_API_KEY" https://api.openai.com/v1/models
```

### Q5: 端口被占用

```bash
# 查看端口占用
sudo lsof -i :8000

# 杀掉占用进程
sudo kill -9 <PID>
```

---

## 快速部署脚本

将以下脚本保存为 `deploy.sh`：

```bash
#!/bin/bash
# CTF-Agent 一键部署脚本

set -e

echo "=== CTF-Agent 部署脚本 ==="

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用root权限运行"
    exit 1
fi

# 1. 更新系统
echo "[1/8] 更新系统..."
apt update && apt upgrade -y

# 2. 安装依赖
echo "[2/8] 安装依赖..."
apt install -y git curl wget vim ufw docker.io nginx python3.10 python3-pip nodejs npm

# 3. 配置防火墙
echo "[3/8] 配置防火墙..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# 4. 克隆项目
echo "[4/8] 克隆项目..."
cd /opt
git clone https://github.com/yinyu-cybersecurity/Multi-Scenario-Security-Intelligent-Agent.git ctf-agent
cd ctf-agent

# 5. 安装Python依赖
echo "[5/8] 安装Python依赖..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 6. 构建前端
echo "[6/8] 构建前端..."
cd frontend
npm install
npm run build
mkdir -p /var/www/ctf-agent
cp -r dist/* /var/www/ctf-agent/
cd ..

# 7. 构建Docker镜像
echo "[7/8] 构建Docker镜像..."
chmod +x scripts/build-images.sh
./scripts/build-images.sh

# 8. 创建配置文件
echo "[8/8] 创建配置..."
cp config.yaml.example config.yaml
echo "请编辑 /opt/ctf-agent/config.yaml 填入API密钥"

echo "=== 部署完成 ==="
echo "下一步："
echo "1. 编辑 config.yaml 配置API密钥"
echo "2. 启动后端服务: systemctl start ctf-agent"
echo "3. 配置域名和HTTPS"
```

使用方法：

```bash
chmod +x deploy.sh
sudo ./deploy.sh
```

---

## 总结

部署完成后，访问 `https://your-domain.com` 即可使用CTF-Agent。

**关键步骤回顾**：
1. ✅ 服务器环境准备（Docker、Python、Node.js）
2. ✅ 前端构建（npm run build）
3. ✅ 后端配置（config.yaml）
4. ✅ Docker工具镜像构建
5. ✅ Nginx反向代理配置
6. ✅ HTTPS证书配置
7. ✅ 进程管理（Systemd服务）

**日常维护**：
- 查看日志：`journalctl -u ctf-agent -f`
- 重启服务：`systemctl restart ctf-agent`
- 更新代码：`git pull && systemctl restart ctf-agent`
- 更新SSL：`certbot renew`

如有问题，查看日志或提交Issue。