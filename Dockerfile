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

# 下载 nuclei
RUN wget -q -O /tmp/nuclei.zip https://ghp.ci/https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei || true

# 下载 ffuf
RUN wget -q -O /tmp/ffuf.tar.gz https://ghp.ci/https://github.com/projectdiscovery/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/ffuf || true

# 下载 httpx
RUN wget -q -O /tmp/httpx.zip https://ghp.ci/https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip && \
    unzip -o /tmp/httpx.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/httpx || true

# 下载 subfinder
RUN wget -q -O /tmp/subfinder.tar.gz https://ghp.ci/https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_amd64.tar.gz && \
    tar -xzf /tmp/subfinder.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/subfinder || true

# 下载 httprobe
RUN wget -q -O /usr/local/bin/httprobe https://ghp.ci/https://github.com/tomnomnom/httprobe/releases/download/v0.2/httprobe-linux-amd64 && \
    chmod +x /usr/local/bin/httprobe || true

# 下载 qsreplace
RUN wget -q -O /usr/local/bin/qsreplace https://ghp.ci/https://github.com/tomnomnom/qsreplace/releases/download/v0.0.2/qsreplace-linux-amd64 && \
    chmod +x /usr/local/bin/qsreplace || true

# 安装 Dalfox (XSS 扫描工具)
RUN go install github.com/hahwul/dalfox/v2@latest && \
    cp /root/go/bin/dalfox /usr/local/bin/dalfox && \
    chmod +x /usr/local/bin/dalfox || true

# 安装 msfvenom（使用 gem 安装，替代完整 Metasploit）
RUN gem install msfvenom || true

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

# 克隆 GitHub 仓库
RUN git clone --depth 1 https://gitee.com/mirrors/dirsearch.git /app/thirdparty/dirsearch || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/swisskyrepo/SSRFmap.git /app/thirdparty/SSRFmap || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/tarunkant/Gopherus.git /app/thirdparty/Gopherus || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/ambionics/phpggc.git /app/thirdparty/phpggc || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/ticarpi/jwt_tool.git /app/thirdparty/jwt_tool || true
RUN git clone --depth 1 https://gitee.com/mirrors/SecLists.git /app/thirdparty/SecLists || true
RUN git clone --depth 1 https://gitee.com/mirrors/PayloadsAllTheThings.git /app/thirdparty/PayloadsAllTheThings || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/Threezh1/JSFinder.git /app/thirdparty/jsfinder || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/enjoiz/XXEinjector.git /app/thirdparty/xxe-injector || true

# php-filter-chain（新增）
RUN git clone --depth 1 https://ghp.ci/https://github.com/synacktiv/php_filter_chain.git /app/thirdparty/php_filter_chain || true

# AD 工具
RUN git clone --depth 1 https://ghp.ci/https://github.com/leechristensen/ADCollector.git /app/thirdparty/adcollector || true
RUN git clone --depth 1 https://ghp.ci/https://github.com/topotam/PetitPotam.git /app/thirdparty/PetitPotam || true

# AJPShooter (Ghostcat CVE-2020-1938)
RUN git clone --depth 1 https://ghp.ci/https://github.com/00theway/Ghostcat-CNVD-2020-10487.git /app/thirdparty/ajpshooter || true

# marshalsec
RUN git clone --depth 1 https://ghp.ci/https://github.com/mbechler/marshalsec.git /app/thirdparty/marshalsec || true
RUN cd /app/thirdparty/marshalsec && mvn package -DskipTests 2>/dev/null && cp target/marshalsec-*.jar /app/thirdparty/marshalsec.jar || true

# fscan 编译
RUN git clone --depth 1 https://ghp.ci/https://github.com/shadow1ng/fscan.git /app/thirdparty/fscan || true
RUN cd /app/thirdparty/fscan && go build -o /usr/local/bin/fscan . || true

# 下载 jar 文件
RUN wget -q -O /app/thirdparty/ysoserial.jar https://ghp.ci/https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar || true
RUN wget -q -O /app/thirdparty/JNDIExploit.jar https://ghp.ci/https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar || true

# frp
RUN wget -q https://ghp.ci/https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz && \
    tar -xzf frp_0.52.3_linux_amd64.tar.gz -C /opt/frp --strip-components=1 && \
    rm -f frp_0.52.3_linux_amd64.tar.gz || true

# Windows 工具
RUN wget -q -O /opt/tools/windows/fscan.exe https://ghp.ci/https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan.exe || true
RUN wget -q -O /opt/tools/potato/PrintSpoofer64.exe https://ghp.ci/https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe || true
RUN wget -q -O /opt/tools/potato/GodPotato.exe https://ghp.ci/https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato_Net40.exe || true
RUN wget -q -O /opt/tools/windows/Rubeus.exe https://ghp.ci/https://github.com/GhostPack/Rubeus/releases/download/2.2.0/Rubeus.exe || true

# mimikatz（Windows）
RUN wget -q -O /tmp/mimikatz.zip https://ghp.ci/https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip && \
    unzip -o /tmp/mimikatz.zip -d /opt/tools/windows/mimikatz_temp/ && \
    mv /opt/tools/windows/mimikatz_temp/x64/mimikatz.exe /opt/tools/windows/mimikatz.exe && \
    rm -rf /tmp/mimikatz.zip /opt/tools/windows/mimikatz_temp && \
    chmod +x /opt/tools/windows/mimikatz.exe || true

# xray
RUN wget -q -O /tmp/xray.zip https://ghp.ci/https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray && \
    mv /tmp/xray/xray_linux_amd64 /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray* || true

# 创建软链接
RUN mkdir -p /opt/linux && \
    ln -sf /usr/local/bin/fscan /opt/linux/fscan && \
    ln -sf /usr/local/bin/nuclei /opt/linux/nuclei && \
    ln -sf /usr/local/bin/xray /opt/linux/xray && \
    ln -sf /usr/local/bin/ffuf /opt/linux/ffuf && \
    ln -sf /usr/local/bin/httpx /opt/linux/httpx && \
    ln -sf /usr/local/bin/subfinder /opt/linux/subfinder && \
    ln -sf /app/thirdparty/dirsearch/dirsearch.py /usr/local/bin/dirsearch && \
    ln -sf /app/thirdparty/php_filter_chain/php_filter_chain.py /usr/local/bin/php-filter-chain && \
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