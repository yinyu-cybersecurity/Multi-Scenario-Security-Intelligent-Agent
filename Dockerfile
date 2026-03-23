# CTF-Agent Dockerfile
# Ubuntu-based image with all security tools

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.11 python3.11-venv python3-pip \
    git curl wget unzip \
    nmap openjdk-17-jdk maven \
    ruby php-cli libssl-dev libssh-dev \
    libimage-exiftool-perl binwalk foremost \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22 (required for nuclei and other tools)
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

# Set Go environment
ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin

# Install Go tools (split to allow partial failures)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/ffuf/v2/cmd/ffuf@latest || \
    go install -v github.com/projectdiscovery/ffuf/cmd/ffuf@latest || true
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
RUN go install -v github.com/tomnomnom/httprobe@latest || true
RUN go install -v github.com/tomnomnom/gf@latest || true
RUN go install -v github.com/tomnomnom/qsreplace@latest || true

# Install Python tools via pipx (split to allow partial failures)
RUN pip3 install pipx && pipx ensurepath
RUN pipx install sqlmap || true
RUN pipx install fenjing || true
RUN pipx install flask-unsign || true
RUN pipx install crackmapexec || pipx install cme || true
RUN pipx install bloodhound-python || true
RUN pipx install impacket || true
RUN pipx install pwntools || true
RUN pipx install ROPgadget || true
RUN pipx install jwt-tool || true
RUN pipx install dictutils || true
RUN pipx install xsstrike || true

# Install Ruby tools
RUN gem install zsteg one_gadget

# Create app and thirdparty directories
WORKDIR /app
RUN mkdir -p /app/thirdparty /app/data/tool_outputs /app/data/tool_raw_logs /app/data/frp /app/.memory /app/log

# ========== 开源安全工具 ==========
# SSRF工具
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /app/thirdparty/SSRFmap 2>/dev/null || true
RUN git clone --depth 1 https://github.com/tarunkant/Gopherus.git /app/thirdparty/Gopherus 2>/dev/null || true

# 内网综合扫描
RUN git clone --depth 1 https://github.com/shadow1ng/fscan.git /app/thirdparty/fscan 2>/dev/null || true
RUN git clone --depth 1 https://github.com/lcvvvv/kscan.git /app/thirdparty/kscan 2>/dev/null || true

# OA漏洞利用工具
RUN git clone --depth 1 https://github.com/NS-Sp4ce/WeaverExploit.git /app/thirdparty/WeaverExploit 2>/dev/null || true
RUN git clone --depth 1 https://github.com/NS-Sp4ce/SeeyonExploit.git /app/thirdparty/SeeyonExploit 2>/dev/null || true
RUN git clone --depth 1 https://github.com/peiqiF4ck/TongdaOA-exploit.git /app/thirdparty/TongdaOA-exploit 2>/dev/null || true

# AI安全测试
RUN git clone --depth 1 https://github.com/leondz/garak.git /app/thirdparty/garak 2>/dev/null || true
RUN git clone --depth 1 https://github.com/agencyenterprise/promptinject.git /app/thirdparty/promptinject 2>/dev/null || true

# Java反序列化工具
RUN wget -q -O /app/thirdparty/ysoserial.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar 2>/dev/null || echo "ysoserial download skipped"
RUN wget -q -O /app/thirdparty/JNDIExploit.jar https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar 2>/dev/null || echo "JNDIExploit download skipped"
RUN git clone --depth 1 https://github.com/mbechler/marshalsec.git /app/thirdparty/marshalsec 2>/dev/null || true

# 其他实用工具
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /app/thirdparty/phpggc 2>/dev/null || true
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /app/thirdparty/jwt_tool 2>/dev/null || true
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /app/thirdparty/SecLists 2>/dev/null || true
RUN git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /app/thirdparty/PayloadsAllTheThings 2>/dev/null || true
RUN git clone --depth 1 https://github.com/fofapro/fapro.git /app/thirdparty/fapro 2>/dev/null || true

# frp代理
RUN wget -q https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz && \
    tar -xzf frp_0.52.3_linux_amd64.tar.gz -C /app/data/frp --strip-components=1 && \
    rm frp_0.52.3_linux_amd64.tar.gz 2>/dev/null || echo "frp download skipped"

# Create Python virtual environment and install dependencies FIRST (before copying code)
COPY requirements.txt .
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install PyTorch CPU version first (avoid 2GB+ CUDA dependencies)
RUN pip install --upgrade pip && \
    pip install torch --index-url https://download.pytorch.org/whl/cpu

# Install other dependencies (sentence-transformers won't reinstall torch)
RUN pip install -r requirements.txt

# NOW copy application files (changes here won't trigger dependency reinstall)
COPY app/*.py ./
COPY app/topology ./topology/
COPY tools/ ./tools/
COPY internal_network/ ./internal_network/
COPY crypto/ ./crypto/
COPY pwn/ ./pwn/
COPY reverse/ ./reverse/
COPY misc/ ./misc/
COPY memory/ ./memory/
COPY rag_builder/ ./rag_builder/

# Copy config template
COPY config.yaml.example /app/config.yaml.example

# Copy self-check script
COPY self_check.py /app/self_check.py

# Update nuclei templates
RUN /root/go/bin/nuclei -update-templates 2>/dev/null || true

# Expose ports (for reverse shells, proxies, etc.)
EXPOSE 1080 8080 4444

# Set entrypoint
ENTRYPOINT ["/opt/venv/bin/python", "/app/ctf_agent_graph.py"]
CMD ["--help"]