# CTF 综合工具镜像 - 合并所有工具
# 包含: Web安全、Pwn、AD域、Misc、反序列化工具

# 使用阿里云镜像加速
FROM python:3.11-slim

# 立即替换为阿里云源（在第一个RUN之前）
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null || true

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# ============================================
# 基础系统工具（一次性安装）
# ============================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # 基础工具
    curl wget git unzip vim \
    # 网络工具
    nmap netcat-openbsd \
    # Pwn工具
    gdb gdb-multiarch libc6-dev-i386 \
    # AD域依赖
    libkrb5-dev libffi-dev build-essential \
    # Misc工具
    binwalk foremost exiftool \
    # 其他
    libssl-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# ============================================
# Go 环境（用于Web工具）
# ============================================
RUN wget -q https://mirrors.aliyun.com/golang/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin
ENV GOPROXY=https://goproxy.cn,direct

# 仅安装核心Web工具（减少编译时间）
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ============================================
# Python 工具（pipx 管理）
# ============================================
# pip配置阿里云镜像
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ && \
    pip config set global.trusted-host mirrors.aliyun.com

RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

# Web安全
RUN pipx install sqlmap || true

# AD域渗透
RUN pipx install crackmapexec || true
RUN pipx install impacket || true
RUN pipx install bloodhound || true
RUN pipx install certipy-ad || true

# Pwn
RUN pip install --no-cache-dir pwntools ROPgadget capstone || true

# ============================================
# 其他工具
# ============================================
# fscan
RUN wget -q -O /usr/local/bin/fscan https://github.com/shadow1ng/fscan/releases/download/1.8.2/fscan && \
    chmod +x /usr/local/bin/fscan || echo "fscan下载失败，跳过"

# dirsearch
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch && \
    pip install -r /opt/dirsearch/requirements.txt && \
    ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

# jwt_tool
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip install -r /opt/jwt_tool/requirements.txt && \
    ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# ============================================
# 创建非root用户
# ============================================
RUN useradd -r -s /bin/false ctfuser && \
    mkdir -p /workspace && \
    chown -R ctfuser:ctfuser /workspace /opt /root/.local 2>/dev/null || true

WORKDIR /workspace
USER ctfuser

CMD ["sleep", "infinity"]