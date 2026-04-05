FROM kalilinux/kali-rolling

# 安装Python和基础依赖
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 安装Python包
RUN pip3 install --no-cache-dir \
    httpx \
    mcp \
    litellm

# 创建工作目录
WORKDIR /app

# 复制项目文件
COPY app /app/app
COPY mcp_servers /app/mcp_servers
COPY skills /app/skills
COPY settings.json /app/settings.json
COPY requirements.txt /app/requirements.txt

# 安装项目依赖
RUN pip3 install --no-cache-dir -r requirements.txt 2>/dev/null || true

# 创建日志目录
RUN mkdir -p /app/logs

# 启动CLI
CMD ["python3", "-m", "app.cli"]