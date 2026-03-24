# CTF-Agent Dockerfile (Optimized)
# Ubuntu-based image with all security tools
# 优化构建顺序：变化少的在前，变化多的在后

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# ===== Layer 1: 系统依赖 (几乎不变) =====
# 镜像源替换与apt-get合并为一个RUN，避免增加新层
RUN sed -i 's@archive.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv python3-pip \
    git curl wget unzip \
    nmap openjdk-17-jdk maven \
    ruby php-cli libssl-dev libssh-dev \
    libimage-exiftool-perl binwalk foremost \
    libmagic1 \
    proxychains4 \
    && rm -rf /var/lib/apt/lists/*

# ===== Layer 2: Go 环境 (几乎不变) =====
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin

# ===== Layer 3: Go 工具 (偶尔变) =====
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/ffuf/v2/cmd/ffuf@latest || \
    go install -v github.com/projectdiscovery/ffuf/cmd/ffuf@latest || true

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true && \
    go install -v github.com/tomnomnom/httprobe@latest || true && \
    go install -v github.com/tomnomnom/gf@latest || true && \
    go install -v github.com/tomnomnom/qsreplace@latest || true

# ===== Layer 4: Python/Ruby 工具 (偶尔变) =====
RUN pip3 install pipx && pipx ensurepath && \
    pipx install sqlmap || true && \
    pipx install fenjing || true && \
    pipx install flask-unsign || true && \
    pipx install crackmapexec || pipx install cme || true && \
    pipx install bloodhound-python || true && \
    pipx install impacket || true && \
    pipx install pwntools || true && \
    pipx install ROPgadget || true && \
    pipx install jwt-tool || true && \
    pipx install paramiko || true

RUN gem install zsteg one_gadget

# ===== Layer 5: 创建目录 =====
WORKDIR /app
RUN mkdir -p /app/thirdparty \
    /app/data/tool_outputs \
    /app/data/tool_raw_logs \
    /app/data/sessions \
    /app/data/tunnels \
    /app/.memory \
    /app/log

# ===== Layer 5.5: 工具目录 (放在/opt下，避免被volume挂载覆盖) =====
RUN mkdir -p /opt/tools/potato \
    /opt/tools/ad \
    /opt/tools/linux \
    /opt/tools/windows \
    /opt/frp

# ===== Layer 6: 下载所有第三方工具 (偶尔变，但都在代码复制之前) =====
# 网络失败不影响构建，所有下载命令都有容错处理
RUN echo "Starting git clones..."; \
    # SSRF工具
    git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /app/thirdparty/SSRFmap 2>/dev/null || true; \
    git clone --depth 1 https://github.com/tarunkant/Gopherus.git /app/thirdparty/Gopherus 2>/dev/null || true; \
    # OA漏洞利用
    git clone --depth 1 https://github.com/NS-Sp4ce/WeaverExploit.git /app/thirdparty/WeaverExploit 2>/dev/null || true; \
    git clone --depth 1 https://github.com/NS-Sp4ce/SeeyonExploit.git /app/thirdparty/SeeyonExploit 2>/dev/null || true; \
    git clone --depth 1 https://github.com/peiqiF4ck/TongdaOA-exploit.git /app/thirdparty/TongdaOA-exploit 2>/dev/null || true; \
    # AI安全
    git clone --depth 1 https://github.com/leondz/garak.git /app/thirdparty/garak 2>/dev/null || true; \
    git clone --depth 1 https://github.com/agencyenterprise/promptinject.git /app/thirdparty/promptinject 2>/dev/null || true; \
    # 其他工具
    git clone --depth 1 https://github.com/ambionics/phpggc.git /app/thirdparty/phpggc 2>/dev/null || true; \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /app/thirdparty/jwt_tool 2>/dev/null || true; \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /app/thirdparty/SecLists 2>/dev/null || true; \
    git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /app/thirdparty/PayloadsAllTheThings 2>/dev/null || true; \
    git clone --depth 1 https://github.com/fofapro/fapro.git /app/thirdparty/fapro 2>/dev/null || true; \
    # AD工具
    git clone --depth 1 https://github.com/topotam/PetitPotam.git /app/thirdparty/PetitPotam 2>/dev/null || true; \
    git clone --depth 1 https://github.com/mbechler/marshalsec.git /app/thirdparty/marshalsec 2>/dev/null || true; \
    # fscan 编译
    git clone --depth 1 https://github.com/shadow1ng/fscan.git /app/thirdparty/fscan 2>/dev/null || true; \
    cd /app/thirdparty/fscan && go build -o /usr/local/bin/fscan . 2>/dev/null || true; \
    echo "Git clones completed"

# 下载二进制文件
RUN echo "Starting binary downloads..."; \
    # Java反序列化
    wget -q -O /app/thirdparty/ysoserial.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar 2>/dev/null || true; \
    wget -q -O /app/thirdparty/JNDIExploit.jar https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar 2>/dev/null || true; \
    echo "Java tools completed"; \
    # frp代理 - Linux版本
    wget -q https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz 2>/dev/null && \
    tar -xzf frp_0.52.3_linux_amd64.tar.gz -C /opt/frp --strip-components=1 2>/dev/null && \
    rm -f frp_0.52.3_linux_amd64.tar.gz || true; \
    # frp代理 - Windows版本
    wget -q https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_windows_amd64.zip 2>/dev/null && \
    unzip -q frp_0.52.3_windows_amd64.zip -d /tmp/frp_win 2>/dev/null && \
    mv /tmp/frp_win/frp_0.52.3_windows_amd64/frpc.exe /opt/tools/windows/ 2>/dev/null || true; \
    mv /tmp/frp_win/frp_0.52.3_windows_amd64/frps.exe /opt/tools/windows/ 2>/dev/null || true; \
    rm -rf frp_0.52.3_windows_amd64.zip /tmp/frp_win || true; \
    echo "frp completed"; \
    # fscan - Linux版本 (已编译到/usr/local/bin/fscan) \
    # fscan - Windows版本
    wget -q -O /opt/tools/windows/fscan.exe https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan.exe 2>/dev/null || true; \
    echo "fscan completed"; \
    # Windows提权工具
    wget -q -O /opt/tools/potato/PrintSpoofer64.exe \
        "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe" 2>/dev/null || true; \
    wget -q -O /opt/tools/potato/SweetPotato.exe \
        "https://github.com/CCob/SweetPotato/raw/master/SweetPotato/bin/Release/SweetPotato.exe" 2>/dev/null || true; \
    wget -q -O /opt/tools/potato/GodPotato.exe \
        "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato_Net40.exe" 2>/dev/null || true; \
    echo "potato tools completed"; \
    # mimikatz
    wget -q -O /tmp/mimikatz.zip \
        "https://github.com/gentilkiwi/mimikatz/releases/download/v2.2.0-20220919/mimikatz_trunk.zip" 2>/dev/null && \
    unzip -q /tmp/mimikatz.zip -d /opt/tools/ 2>/dev/null && \
    rm -f /tmp/mimikatz.zip || true; \
    echo "mimikatz completed"; \
    # nuclei templates
    /root/go/bin/nuclei -update-templates 2>/dev/null || true; \
    # xray 漏洞扫描器
    wget -q -O /tmp/xray.zip https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip 2>/dev/null && \
    unzip -o /tmp/xray.zip -d /tmp/xray_extract 2>/dev/null && \
    mv /tmp/xray_extract/xray_linux_amd64 /usr/local/bin/xray 2>/dev/null || mv /tmp/xray_extract/xray /usr/local/bin/xray 2>/dev/null || true; \
    chmod +x /usr/local/bin/xray 2>/dev/null || true; \
    rm -rf /tmp/xray.zip /tmp/xray_extract || true; \
    echo "Binary downloads completed"

# ===== Layer 7: Python 依赖 (偶尔变) =====
COPY deploy/requirements.txt .
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install -r requirements.txt

# ===== Layer 8: 应用代码 (经常变，放最后) =====
COPY deploy/app/*.py ./
COPY deploy/app/topology ./topology/
COPY deploy/tools/ ./tools/
COPY deploy/internal_network/ ./internal_network/
COPY deploy/remote_executor/ ./remote_executor/
COPY deploy/crypto/ ./crypto/
COPY deploy/pwn/ ./pwn/
COPY deploy/reverse/ ./reverse/
COPY deploy/misc/ ./misc/
COPY deploy/memory/ ./memory/
COPY deploy/rag_builder/ ./rag_builder/
COPY deploy/config.yaml.example /app/config.yaml.example
COPY deploy/self_check.py /app/self_check.py

# ===== 端口暴露 =====
EXPOSE 8000 7000 10800 4444

# ===== 入口点 =====
ENTRYPOINT ["tail", "-f", "/dev/null"]