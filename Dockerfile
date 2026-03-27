FROM ac2-registry.cn-hangzhou.cr.aliyuncs.com/ac2/base:ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# 替换 APT 源为阿里云镜像
RUN sed -i 's@archive.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    sed -i 's@security.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3.11 python3.11-venv python3-pip python3.10-venv \
        git curl wget unzip nmap openjdk-17-jdk maven ruby php-cli \
        libssl-dev libssh-dev libimage-exiftool-perl binwalk foremost \
        libmagic1 proxychains4 hydra && \
    rm -rf /var/lib/apt/lists/*

# 下载 Go（国内镜像）
RUN wget -q https://mirrors.aliyun.com/golang/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin
ENV GOPROXY=https://goproxy.cn,direct

# 下载 httprobe
RUN wget -q -O /usr/local/bin/httprobe https://moeyy.cn/gh-proxy/https://github.com/tomnomnom/httprobe/releases/download/v0.2/httprobe-linux-amd64 && \
    chmod +x /usr/local/bin/httprobe || true

# 下载 qsreplace
RUN wget -q -O /usr/local/bin/qsreplace https://moeyy.cn/gh-proxy/https://github.com/tomnomnom/qsreplace/releases/download/v0.0.2/qsreplace-linux-amd64 && \
    chmod +x /usr/local/bin/qsreplace || true

# 安装 Dalfox (XSS 扫描工具)
RUN go install github.com/hahwul/dalfox/v2@latest && \
    cp /root/go/bin/dalfox /usr/local/bin/dalfox && \
    chmod +x /usr/local/bin/dalfox || true

# 安装完整 Metasploit Framework
RUN apt-get update && apt-get install -y metasploit-framework || true

# Python pip 配置
RUN pip3 install pipx -i https://pypi.tuna.tsinghua.edu.cn/simple && \
    pipx ensurepath

ENV PATH="/root/.local/bin:$PATH"

RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 安装 Python 工具
RUN pipx install sqlmap || true
RUN pipx install fenjing || true
RUN pipx install flask-unsign || true
RUN pipx install impacket || true
RUN pipx install pwntools || true
RUN pipx install ROPgadget || true
RUN pipx install git-hacker || true
RUN pipx install ldapdomaindump || true
RUN pipx install bloodhound || true
RUN pipx install crackmapexec || true

# Ruby gems 国内镜像
RUN gem sources --add https://gems.ruby-china.com/ --remove https://rubygems.org/ || true
RUN gem install zsteg one_gadget || true

WORKDIR /app

RUN mkdir -p /app/thirdparty /app/data/tool_outputs /app/data/tool_raw_logs /app/data/sessions /app/data/tunnels /app/.memory /app/log /opt/tools/potato /opt/tools/ad /opt/tools/linux /opt/tools/windows /opt/frp

# ============ 从本地 thirdparty 复制工具 ============
# 复制二进制工具到 /usr/local/bin
COPY thirdparty/nuclei/nuclei /usr/local/bin/nuclei
COPY thirdparty/xray/xray_linux_amd64 /usr/local/bin/xray
COPY thirdparty/httpx/httpx /usr/local/bin/httpx
COPY thirdparty/ffuf/ffuf /usr/local/bin/ffuf
COPY thirdparty/subfinder/subfinder /usr/local/bin/subfinder
COPY thirdparty/fscan_linux/fscan /usr/local/bin/fscan
RUN chmod +x /usr/local/bin/nuclei /usr/local/bin/xray /usr/local/bin/httpx /usr/local/bin/ffuf /usr/local/bin/subfinder /usr/local/bin/fscan

# 复制 frp
COPY thirdparty/frp/frp_0.52.3_linux_amd64 /opt/frp

# 复制 Git 仓库工具到 /app/thirdparty
COPY thirdparty/SSRFmap /app/thirdparty/SSRFmap
COPY thirdparty/Gopherus /app/thirdparty/Gopherus
COPY thirdparty/phpggc /app/thirdparty/phpggc
COPY thirdparty/jwt_tool /app/thirdparty/jwt_tool
COPY thirdparty/JSFinder /app/thirdparty/jsfinder
COPY thirdparty/XXEinjector /app/thirdparty/xxe-injector
COPY thirdparty/php_filter_chain_generator /app/thirdparty/php_filter_chain
COPY thirdparty/PetitPotam /app/thirdparty/PetitPotam
COPY thirdparty/Ghostcat /app/thirdparty/ajpshooter
COPY thirdparty/marshalsec /app/thirdparty/marshalsec
COPY thirdparty/fscan_windows /opt/tools/windows/fscan
COPY thirdparty/ysoserial/ysoserial-all.jar /app/thirdparty/ysoserial.jar

# marshalsec 编译
RUN cd /app/thirdparty/marshalsec && mvn package -DskipTests 2>/dev/null && cp target/marshalsec-*.jar /app/thirdparty/marshalsec.jar || true

# ============ 保留的 git clone 工具（其他工具）============
# dirsearch
RUN git clone --depth 1 https://gitee.com/mirrors/dirsearch.git /app/thirdparty/dirsearch || true

# SecLists
RUN git clone --depth 1 https://gitee.com/RichardoMrMu/SecLists.git /app/thirdparty/SecLists || true

# PayloadsAllTheThings
RUN git clone --depth 1 https://gitee.com/RichardoMrMu/PayloadsAllTheThings.git /app/thirdparty/PayloadsAllTheThings || true

# 下载 JNDIExploit.jar
RUN wget -q -O /app/thirdparty/JNDIExploit.jar https://moeyy.cn/gh-proxy/https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar || \
    wget -q -O /app/thirdparty/JNDIExploit.jar https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar || true

# Windows 工具

RUN wget -q --timeout=60 --tries=3 -O /opt/tools/potato/PrintSpoofer64.exe https://ghproxy.net/https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe || \
    wget -q --timeout=60 --tries=3 -O /opt/tools/potato/PrintSpoofer64.exe https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe || \
    wget -q --timeout=60 --tries=3 -O /opt/tools/potato/PrintSpoofer64.exe https://moeyy.cn/gh-proxy/https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe || true

RUN wget -q --timeout=60 --tries=2 -O /opt/tools/potato/GodPotato.exe https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato_Net40.exe || \
    wget -q --timeout=60 --tries=2 -O /opt/tools/potato/GodPotato.exe https://gitee.com/uploads/111/685/111/GodPotato_Net40.exe || true

RUN wget -q -O /opt/tools/windows/Rubeus.exe https://moeyy.cn/gh-proxy/https://github.com/GhostPack/Rubeus/releases/download/2.2.0/Rubeus.exe || \
    wget -q -O /opt/tools/windows/Rubeus.exe https://github.com/GhostPack/Rubeus/releases/download/2.2.0/Rubeus.exe || true

# mimikatz（Windows）
RUN wget -q -O /tmp/mimikatz.zip https://moeyy.cn/gh-proxy/https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip && \
    unzip -o /tmp/mimikatz.zip -d /opt/tools/windows/mimikatz_temp/ && \
    mv /opt/tools/windows/mimikatz_temp/x64/mimikatz.exe /opt/tools/windows/mimikatz.exe && \
    rm -rf /tmp/mimikatz.zip /opt/tools/windows/mimikatz_temp && \
    chmod +x /opt/tools/windows/mimikatz.exe || true

# 清理临时文件
RUN rm -rf /tmp/* /var/tmp/* && \
    find /app/thirdparty -name ".git" -type d -exec rm -rf {} + 2>/dev/null || true

# 创建软链接
RUN mkdir -p /opt/linux && \
    ln -sf /usr/local/bin/fscan /opt/linux/fscan && \
    ln -sf /usr/local/bin/nuclei /opt/linux/nuclei && \
    ln -sf /usr/local/bin/xray /opt/linux/xray && \
    ln -sf /usr/local/bin/ffuf /opt/linux/ffuf && \
    ln -sf /usr/local/bin/httpx /opt/linux/httpx && \
    ln -sf /usr/local/bin/subfinder /opt/linux/subfinder && \
    ln -sf /app/thirdparty/dirsearch/dirsearch.py /usr/local/bin/dirsearch && \
    ln -sf /app/thirdparty/php_filter_chain/php_filter_chain_generator.py /usr/local/bin/php-filter-chain && \
    chmod +x /usr/local/bin/dirsearch /usr/local/bin/php-filter-chain

COPY requirements.txt .
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install -r requirements.txt

COPY app/*.py ./
COPY app/state_types ./state_types/
COPY app/topology ./topology/
COPY tools/ ./tools/
COPY internal_network/ ./internal_network/
COPY remote_executor/ ./remote_executor/
COPY crypto/ ./crypto/
COPY pwn/ ./pwn/
COPY reverse/ ./reverse/
COPY misc/ ./misc/
COPY memory/ ./memory/
COPY rag_builder/ ./rag_builder/
COPY config.yaml.example /app/config.yaml.example
COPY self_check.py /app/self_check.py
COPY web/ ./web/

EXPOSE 54565 8000 7000 10800 4444

CMD ["tail", "-f", "/dev/null"]