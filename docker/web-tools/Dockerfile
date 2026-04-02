# CTF Web安全工具镜像
# 包含: nmap, nuclei, httpx, fscan, sqlmap, ffuf, dirsearch, xray等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 替换为阿里云镜像源
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list 2>/dev/null || true

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl wget git unzip \
    libssl-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Go环境
RUN wget -q https://mirrors.aliyun.com/golang/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin
ENV GOPROXY=https://goproxy.cn,direct

# Go工具
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest

# Python工具
RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

RUN pipx install sqlmap || true

# 其他工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    whatweb hydra \
    && rm -rf /var/lib/apt/lists/*

# fscan
RUN wget -q -O /usr/local/bin/fscan https://github.com/shadow1ng/fscan/releases/download/1.8.2/fscan && \
    chmod +x /usr/local/bin/fscan || true

# xray
RUN wget -q -O /tmp/xray.zip https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip && \
    unzip /tmp/xray.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/xray && \
    rm /tmp/xray.zip || true

# dirsearch
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch && \
    pip install -r /opt/dirsearch/requirements.txt && \
    ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

# 创建非root用户
RUN useradd -r -s /bin/false ctfuser && \
    chown -R ctfuser:ctfuser /opt/dirsearch /root/.local 2>/dev/null || true

# 工作目录
WORKDIR /workspace

# 切换到非root用户
USER ctfuser

# 默认命令
CMD ["sleep", "infinity"]