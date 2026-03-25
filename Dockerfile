# CTF-Agent Dockerfile (Optimized)
# Ubuntu-based image with all security tools
# 优化构建顺序：变化少的在前，变化多的在后

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# ===== Layer 1: 系统依赖 (几乎不变) =====
RUN sed -i 's@archive.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv python3-pip python3.10-venv \
    git curl wget unzip \
    nmap openjdk-17-jdk maven \
    ruby php-cli libssl-dev libssh-dev \
    libimage-exiftool-perl binwalk foremost \
    libmagic1 \
    proxychains4 \
    hydra \
    && rm -rf /var/lib/apt/lists/*

# ===== Layer 2: Go 环境 (几乎不变) =====
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin

# ===== Layer 3: Go 工具 (偶尔变) =====
# 使用 GitHub Releases 下载二进制文件（避免网络问题）
RUN echo "Installing Go tools..." && \
    # nuclei
    wget -q -O /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip 2>/dev/null && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin 2>/dev/null && chmod +x /usr/local/bin/nuclei || true && \
    # ffuf
    wget -q -O /tmp/ffuf.tar.gz https://github.com/projectdiscovery/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz 2>/dev/null && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin 2>/dev/null && chmod +x /usr/local/bin/ffuf || true && \
    # httpx
    wget -q -O /tmp/httpx.zip https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip 2>/dev/null && \
    unzip -o /tmp/httpx.zip -d /usr/local/bin 2>/dev/null && chmod +x /usr/local/bin/httpx || true && \
    # subfinder
    wget -q -O /tmp/subfinder.tar.gz https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_amd64.tar.gz 2>/dev/null && \
    tar -xzf /tmp/subfinder.tar.gz -C /usr/local/bin 2>/dev/null && chmod +x /usr/local/bin/subfinder || true && \
    # httprobe
    wget -q -O /usr/local/bin/httprobe https://github.com/tomnomnom/httprobe/releases/download/v0.2/httprobe-linux-amd64 2>/dev/null && \
    chmod +x /usr/local/bin/httprobe || true && \
    # gf
    wget -q -O /tmp/gf.tar.gz https://github.com/tomnomnom/gf/releases/download/v0.0.3/gf-linux-amd64.tar.gz 2>/dev/null && \
    tar -xzf /tmp/gf.tar.gz -C /usr/local/bin 2>/dev/null && chmod +x /usr/local/bin/gf || true && \
    # qsreplace
    wget -q -O /usr/local/bin/qsreplace https://github.com/tomnomnom/qsreplace/releases/download/v0.0.2/qsreplace-linux-amd64 2>/dev/null && \
    chmod +x /usr/local/bin/qsreplace || true && \
    rm -rf /tmp/*.zip /tmp/*.tar.gz && \
    echo "Go tools installation completed"

# ===== Layer 4: Python/Ruby 工具 (偶尔变) =====
RUN pip3 install pipx && \
    pipx ensurepath && \
    echo 'export PATH="/root/.local/bin:$PATH"' >> ~/.bashrc

ENV PATH="/root/.local/bin:$PATH"

# 安装 Python 工具
RUN pipx install sqlmap || true && \
    pipx install fenjing || true && \
    pipx install flask-unsign || true && \
    pipx install impacket || true && \
    pipx install pwntools || true && \
    pipx install ROPgadget || true && \
    pipx install git+https://github.com/epsylon/xsser.git || true && \
    pipx install git+https://github.com/Porchetta-Industries/CrackMapExec.git || true && \
    pipx install git+https://github.com/fox-it/BloodHound.py.git || true && \
    # GitHacker - 手动克隆安装
    (git clone --depth 1 https://github.com/WangYihang/GitHacker.git /tmp/githacker && \
     cd /tmp/githacker && pip install . || true && \
     rm -rf /tmp/githacker) || true

# Metasploit Framework 安装
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    chmod 755 msfinstall && \
    ./msfinstall 2>/dev/null || true && \
    rm -f msfinstall || true

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

# ===== Layer 5.5: 工具目录 =====
RUN mkdir -p /opt/tools/potato \
    /opt/tools/ad \
    /opt/tools/linux \
    /opt/tools/windows \
    /opt/frp

# ===== Layer 6: 下载所有第三方工具 =====
RUN echo "Starting git clones..."; \
    # dirsearch 目录扫描
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git /app/thirdparty/dirsearch 2>/dev/null || true; \
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
    git clone --depth 1 https://github.com/0xdea/ad-attacks.git /app/thirdparty/ad-attacks 2>/dev/null || true; \
    # AJPShooter (Ghostcat)
    git clone --depth 1 https://github.com/00theway/Ghostcat-CNVD-2020-10487.git /app/thirdparty/ajpshooter 2>/dev/null || true; \
    # JSFinder
    git clone --depth 1 https://github.com/Threezh1/JSFinder.git /app/thirdparty/jsfinder 2>/dev/null || true; \
    # xxe-injector
    git clone --depth 1 https://github.com/enjoiz/XXEinjector.git /app/thirdparty/xxe-injector 2>/dev/null || true; \
    # marshalsec 编译
    git clone --depth 1 https://github.com/mbechler/marshalsec.git /app/thirdparty/marshalsec 2>/dev/null || true; \
    cd /app/thirdparty/marshalsec && mvn package -DskipTests 2>/dev/null && \
    cp target/marshalsec-*.jar /app/thirdparty/marshalsec.jar 2>/dev/null || true; \
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
    unzip -q /tmp/mimikatz.zip -d /tmp/mimikatz_extract 2>/dev/null && \
    mv /tmp/mimikatz_extract/mimikatz_trunk/x64 /opt/tools/ 2>/dev/null || true && \
    mv /tmp/mimikatz_extract/mimikatz_trunk/Win32 /opt/tools/ 2>/dev/null || true && \
    rm -rf /tmp/mimikatz.zip /tmp/mimikatz_extract || true; \
    echo "mimikatz completed"; \
    # Rubeus
    wget -q -O /opt/tools/windows/Rubeus.exe \
        "https://github.com/GhostPack/Rubeus/releases/download/2.2.0/Rubeus.exe" 2>/dev/null || true; \
    echo "Rubeus completed"; \
    # nuclei templates
    /root/go/bin/nuclei -update-templates 2>/dev/null || true; \
    # xray 漏洞扫描器
    wget -q -O /tmp/xray.zip https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip 2>/dev/null && \
    unzip -o /tmp/xray.zip -d /tmp/xray_extract 2>/dev/null && \
    mv /tmp/xray_extract/xray_linux_amd64 /usr/local/bin/xray 2>/dev/null || mv /tmp/xray_extract/xray /usr/local/bin/xray 2>/dev/null || true; \
    chmod +x /usr/local/bin/xray 2>/dev/null || true; \
    rm -rf /tmp/xray.zip /tmp/xray_extract || true; \
    echo "Binary downloads completed"

# ===== Layer 6.5: Linux工具符号链接 =====
# 为HTTP服务器创建Linux工具的符号链接
# HTTP服务器根目录为/opt，/usr/local/bin/下的工具需要链接到这里
RUN mkdir -p /opt/linux && \
    # fscan
    ln -sf /usr/local/bin/fscan /opt/linux/fscan && \
    # nuclei
    ln -sf /usr/local/bin/nuclei /opt/linux/nuclei && \
    # xray
    ln -sf /usr/local/bin/xray /opt/linux/xray && \
    # ffuf
    ln -sf /usr/local/bin/ffuf /opt/linux/ffuf && \
    # httpx
    ln -sf /usr/local/bin/httpx /opt/linux/httpx && \
    # subfinder
    ln -sf /usr/local/bin/subfinder /opt/linux/subfinder && \
    # httprobe
    ln -sf /usr/local/bin/httprobe /opt/linux/httprobe && \
    # gf
    ln -sf /usr/local/bin/gf /opt/linux/gf && \
    # qsreplace
    ln -sf /usr/local/bin/qsreplace /opt/linux/qsreplace && \
    echo "Linux tool symlinks created in /opt/linux/"

# ===== Layer 7: Python 依赖 (偶尔变) =====
COPY deploy/requirements.txt .
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip && \
    pip install torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install -r requirements.txt

# ===== Layer 8: 应用代码 (经常变，放最后) =====
COPY deploy/app/*.py ./
COPY deploy/app/state_types ./state_types/
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
COPY deploy/refactoring_test.py /app/refactoring_test.py
COPY deploy/web/ ./web/

# ===== 端口暴露 =====
EXPOSE 8000 7000 10800 4444

# ===== 入口点 =====
CMD ["tail", "-f", "/dev/null"]