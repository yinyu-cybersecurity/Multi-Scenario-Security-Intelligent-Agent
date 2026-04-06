# =============================================================================
# CTF-Agent Dockerfile - 企业级标准
#
# 基于 Kali Linux，预装常用渗透工具
# 多阶段构建：Stage 1 安装系统工具, Stage 2 安装 Python 依赖
# =============================================================================

FROM kalilinux/kali-rolling

# 避免交互式安装
ENV DEBIAN_FRONTEND=noninteractive

# ---- Stage 1: System packages + Security tools ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    # 基础工具
    git \
    curl \
    wget \
    jq \
    vim-tiny \
    ca-certificates \
    locales \
    procps \
    # 网络工具
    netcat-traditional \
    socat \
    dnsutils \
    iputils-ping \
    net-tools \
    openssl \
    proxychains4 \
    # === 渗透测试工具 ===
    # 信息收集
    nmap \
    whatweb \
    masscan \
    # Web 安全
    sqlmap \
    ffuf \
    dirb \
    nikto \
    gobuster \
    wfuzz \
    # 密码破解
    john \
    hydra \
    medusa \
    hashcat \
    # 二进制分析
    binwalk \
    gdb \
    radare2 \
    # 漏洞利用
    exploitdb \
    metasploit-framework \
    # 内网渗透
    crackmapexec \
    impacket-scripts \
    responder \
    # 其他
    seclists \
    wordlists \
    && rm -rf /var/lib/apt/lists/*

# 设置 locale
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# ---- Stage 2: Python dependencies ----
WORKDIR /app

# 先复制 requirements，利用 Docker 缓存
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ---- Stage 3: Application code ----
COPY app /app/app
COPY mcp_servers /app/mcp_servers
COPY skills /app/skills
COPY settings.json /app/settings.json

# 创建运行时目录
RUN mkdir -p /app/logs /app/workspace /tmp/ctf

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import app.settings; print('ok')" || exit 1

# 默认入口：比赛自动模式
# 覆盖方式: docker run ... python3 -m app.cli http://target
CMD ["python3", "-m", "app.cli", "--competition"]
