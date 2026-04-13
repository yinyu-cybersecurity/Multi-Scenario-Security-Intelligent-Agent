# =============================================================================
# CTF-Agent Dockerfile
#
# 基于官方完整 Kali Linux 镜像（预装所有渗透工具）
# 仅安装 Python 运行环境和项目依赖
# =============================================================================

FROM kalilinux/kali-rolling

# 避免交互式安装
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# 设置 locale
RUN apt-get update && apt-get install -y --no-install-recommends locales \
    && if [ -f /etc/locale.gen ]; then sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen; fi \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# 设置清华源 + 阿里源（国内加速，HTTP 协议）
RUN echo "deb http://mirrors.tuna.tsinghua.edu.cn/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/kali kali-rolling main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    golang-go \
    git \
    wget \
    unzip \
    kali-linux-default \
    && rm -rf /var/lib/apt/lists/*

# 编译 fscan + 安装 nuclei
RUN cd /tmp && git clone --depth 1 https://github.com/shadow1ng/fscan.git \
    && cd fscan && go build -o /usr/local/bin/fscan . \
    && cd / && rm -rf /tmp/fscan \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && cp /root/go/bin/nuclei /usr/local/bin/ \
    && nuclei -update-templates

# ---- Application ----
WORKDIR /app

# 先复制 requirements，利用 Docker 缓存
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# 复制项目代码和配置
COPY app /app/app
COPY mcp_servers /app/mcp_servers
COPY skills_v2 /app/skills_v2
COPY settings.json /app/settings.json
COPY .env /app/.env

# 创建运行时目录
RUN mkdir -p /app/logs /app/workspace /tmp/ctf

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import app.settings; print('ok')" || exit 1

# 默认入口：比赛自动模式
# 覆盖方式: docker run ... python3 -m app.cli http://target
# default:dockerfile.security.last-user-not-non-root.last-user-not-non-root
# default:dockerfile.security.missing-non-root-user.missing-non-root-user
# Running as root is intentional - CTF tools (nmap, hashcat, metasploit) require root
USER root

CMD ["python3", "-m", "app.cli", "--competition"]
