# CTF-Agent 2.0 Dockerfile
# 基于 Ubuntu 22.04，集成65+安全工具

FROM ac2-registry.cn-hangzhou.cr.aliyuncs.com/ac2/base:ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# ============================================
# 基础环境配置
# ============================================
RUN sed -i 's@archive.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3.11 python3.11-venv python3-pip \
        git curl wget unzip nmap openjdk-17-jdk openjdk-8-jdk maven ruby php-cli \
        libssl-dev libssh-dev libimage-exiftool-perl binwalk foremost \
        libmagic1 proxychains4 hydra && \
    rm -rf /var/lib/apt/lists/*

# Java环境（marshalsec需要Java 8）
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Go环境
RUN wget -q https://mirrors.aliyun.com/golang/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin
ENV GOPROXY=https://goproxy.cn,direct

# ============================================
# Go工具安装
# ============================================
# httprobe & qsreplace
RUN wget -q -O /usr/local/bin/httprobe https://moeyy.cn/gh-proxy/https://github.com/tomnomnom/httprobe/releases/download/v0.2/httprobe-linux-amd64 && \
    chmod +x /usr/local/bin/httprobe || true && \
    wget -q -O /usr/local/bin/qsreplace https://moeyy.cn/gh-proxy/https://github.com/tomnomnom/qsreplace/releases/download/v0.0.2/qsreplace-linux-amd64 && \
    chmod +x /usr/local/bin/qsreplace || true

# dalfox (XSS扫描)
RUN go install github.com/hahwul/dalfox/v2@latest && \
    cp /root/go/bin/dalfox /usr/local/bin/ && chmod +x /usr/local/bin/dalfox || true

# gobuster (目录爆破)
RUN go install github.com/OJ/gobuster/v3@latest && \
    cp /root/go/bin/gobuster /usr/local/bin/ && chmod +x /usr/local/bin/gobuster || true

# ============================================
# Python工具安装
# ============================================
RUN pip3 install pipx -i https://pypi.tuna.tsinghua.edu.cn/simple && \
    pipx ensurepath

ENV PATH="/root/.local/bin:$PATH"
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 核心Python安全工具
RUN pipx install sqlmap || true
RUN pipx install fenjing || true
RUN pipx install flask-unsign || true
RUN pipx install impacket || true
RUN pipx install pwntools || true
RUN pipx install ROPgadget || true
RUN pipx install git-hacker || true
RUN pipx install ldapdomaindump || true
RUN pipx install bloodhound || true
RUN pipx install certipy-ad || true
RUN pipx install pywhisker || true

# crackmapexec依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev build-essential libxml2-dev libxslt1-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install git+https://gitee.com/mirrors/CrackMapExec.git || \
    pipx install git+https://github.com/Porchetta-Industries/CrackMapExec.git || true

# kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/kubectl || true

# Ruby工具
RUN gem sources --add https://gems.ruby-china.com/ --remove https://rubygems.org/ || true
RUN gem install zsteg one_gadget whatweb || true

# ============================================
# 工作目录
# ============================================
WORKDIR /app

# 创建必要目录
RUN mkdir -p /app/thirdparty /app/data/tool_outputs /app/data/tool_raw_logs /app/data/sessions /app/data/tunnels /app/data/security_resources /app/.memory /app/log /opt/tools/potato /opt/tools/ad /opt/tools/linux /opt/tools/windows /opt/frp

# ============================================
# 从本地thirdparty复制工具
# ============================================
# 核心扫描工具
COPY thirdparty/nuclei/nuclei /usr/local/bin/nuclei
COPY thirdparty/xray/xray_linux_amd64 /usr/local/bin/xray
COPY thirdparty/httpx/httpx /usr/local/bin/httpx
COPY thirdparty/ffuf/ffuf /usr/local/bin/ffuf
COPY thirdparty/subfinder/subfinder /usr/local/bin/subfinder
COPY thirdparty/fscan_linux/fscan /usr/local/bin/fscan
RUN chmod +x /usr/local/bin/nuclei /usr/local/bin/xray /usr/local/bin/httpx /usr/local/bin/ffuf /usr/local/bin/subfinder /usr/local/bin/fscan

# frp内网穿透
COPY thirdparty/frp/frp_0.52.3_linux_amd64 /opt/frp

# Python/脚本工具
COPY thirdparty/SSRFmap /app/thirdparty/SSRFmap
COPY thirdparty/Gopherus /app/thirdparty/Gopherus
COPY thirdparty/phpggc /app/thirdparty/phpggc
COPY thirdparty/jwt_tool /app/thirdparty/jwt_tool
COPY thirdparty/JSFinder /app/thirdparty/jsfinder
COPY thirdparty/XXEinjector /app/thirdparty/xxe-injector
COPY thirdparty/php_filter_chain_generator /app/thirdparty/php_filter_chain
COPY thirdparty/PetitPotam /app/thirdparty/PetitPotam
COPY thirdparty/Ghostcat /app/thirdparty/ajpshooter
COPY thirdparty/Githacker /app/thirdparty/Githacker
COPY thirdparty/marshalsec /app/thirdparty/marshalsec
COPY thirdparty/fscan_windows /opt/tools/windows/fscan

# Java工具
COPY thirdparty/ysoserial/ysoserial-all.jar /app/thirdparty/ysoserial.jar
COPY thirdparty/jndiexploit/JNDIExploit-1.3-SNAPSHOT.jar /app/thirdparty/JNDIExploit.jar

# Windows工具
COPY thirdparty/rubeus/Rubeus.exe /opt/tools/windows/Rubeus.exe

# marshalsec编译
RUN cd /app/thirdparty/marshalsec && \
    (mvn clean package -DskipTests 2>/dev/null && \
     cp target/marshalsec-*-all.jar /app/thirdparty/marshalsec.jar) || \
    echo "Warning: marshalsec compilation failed, ysoserial available as fallback"

# 额外工具
RUN git clone --depth 1 https://gitee.com/mirrors/dirsearch.git /app/thirdparty/dirsearch || true
RUN git clone --depth 1 https://gitee.com/RichardoMrMu/PayloadsAllTheThings.git /app/data/security_resources/PayloadsAllTheThings || true

# mimikatz下载
RUN mkdir -p /opt/tools/windows && \
    (wget -q -O /tmp/mimikatz.zip https://moeyy.cn/gh-proxy/https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip && \
     unzip -o /tmp/mimikatz.zip -d /opt/tools/windows/mimikatz_temp/ && \
     mv /opt/tools/windows/mimikatz_temp/x64/mimikatz.exe /opt/tools/windows/mimikatz.exe && \
     chmod +x /opt/tools/windows/mimikatz.exe) || \
    echo "Warning: mimikatz download failed" && \
    rm -rf /tmp/mimikatz.zip /opt/tools/windows/mimikatz_temp 2>/dev/null || true

# 清理
RUN rm -rf /tmp/* /var/tmp/* && \
    find /app/thirdparty -name ".git" -type d -exec rm -rf {} + 2>/dev/null || true

# 软链接
RUN mkdir -p /opt/linux && \
    ln -sf /usr/local/bin/fscan /opt/linux/fscan && \
    ln -sf /usr/local/bin/nuclei /opt/linux/nuclei && \
    ln -sf /usr/local/bin/xray /opt/linux/xray && \
    ln -sf /usr/local/bin/ffuf /opt/linux/ffuf && \
    ln -sf /usr/local/bin/httpx /opt/linux/httpx && \
    ln -sf /usr/local/bin/subfinder /opt/linux/subfinder && \
    ln -sf /app/thirdparty/dirsearch/dirsearch.py /usr/local/bin/dirsearch && \
    ln -sf /app/thirdparty/php_filter_chain/php_filter_chain_generator.py /usr/local/bin/php-filter-chain && \
    chmod +x /usr/local/bin/dirsearch /usr/local/bin/php-filter-chain && \
    chmod +x /app/thirdparty/Githacker/GitHack.py

# ============================================
# Python依赖安装
# ============================================
COPY requirements.txt .
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:/root/.local/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install -r /app/thirdparty/dirsearch/requirements.txt 2>/dev/null || true

# ============================================
# 应用代码复制
# ============================================
COPY app/*.py ./
COPY app/state_types ./state_types/
COPY app/topology ./topology/
COPY app/tools_v2 ./tools_v2/
COPY app/memory ./memory/
COPY app/agents ./agents/
COPY app/capabilities ./capabilities/
COPY app/coordinator ./coordinator/
COPY app/compressor ./compressor/
COPY app/config ./config/
COPY app/skills ./skills/
COPY app/nodes ./nodes/
COPY app/prompts ./prompts/
COPY app/state ./state/
COPY app/reports ./reports/
COPY config.yaml.example /app/config.yaml.example
COPY self_check.py /app/self_check.py
COPY skills/ /app/skills/
COPY frontend/ ./web/frontend/

# ============================================
# 安全配置 - 创建非root用户并配置sudo
# ============================================
# 注意：CTF工具需要特权操作，配置sudo允许ctfagent执行特定工具
RUN apt-get update && apt-get install -y sudo && rm -rf /var/lib/apt/lists/* && \
    groupadd -r ctfagent && useradd -r -g ctfagent -d /app -s /bin/bash ctfagent && \
    echo "ctfagent ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/ctfagent && \
    chmod 440 /etc/sudoers.d/ctfagent && \
    # 将pipx工具复制到全局可访问位置
    cp -r /root/.local/bin/* /usr/local/bin/ 2>/dev/null || true && \
    chown -R ctfagent:ctfagent /app /opt/venv /opt/frp /opt/tools /root/.local 2>/dev/null || true && \
    chmod -R 755 /root/.local 2>/dev/null || true

# ============================================
# 端口暴露
# ============================================
EXPOSE 54565 8000 7000 10800 4444

# ============================================
# 切换到非root用户（应用层安全）
# 注意：CTF场景需要特权操作，sudo已配置
# ============================================
USER ctfagent

# ============================================
# 启动命令
# ============================================
CMD ["tail", "-f", "/dev/null"]