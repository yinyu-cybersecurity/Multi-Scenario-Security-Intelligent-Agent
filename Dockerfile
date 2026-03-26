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

# 下载 nuclei（使用 moeyy.cn 文件加速）
RUN wget -q -O /tmp/nuclei.zip https://moeyy.cn/gh-proxy/https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f /tmp/nuclei.zip || true

# 下载 ffuf
RUN wget -q -O /tmp/ffuf.tar.gz https://moeyy.cn/gh-proxy/https://github.com/projectdiscovery/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/ffuf && \
    rm -f /tmp/ffuf.tar.gz || true

# 下载 httpx
RUN wget -q -O /tmp/httpx.zip https://moeyy.cn/gh-proxy/https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip && \
    unzip -o /tmp/httpx.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/httpx && \
    rm -f /tmp/httpx.zip || true

# 下载 subfinder
RUN wget -q -O /tmp/subfinder.tar.gz https://moeyy.cn/gh-proxy/https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_linux_amd64.tar.gz && \
    tar -xzf /tmp/subfinder.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/subfinder && \
    rm -f /tmp/subfinder.tar.gz || true

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

# 克隆 GitHub 仓库（使用官方源 + 唯一稳定代理 moeyy.cn/gh-proxy）
# 注意：SecLists 和 PayloadsAllTheThings 的 Gitee 镜像已失效，改用官方源

# 使用 Gitee 上仍然可用的镜像（dirsearch 仍在）
RUN git clone --depth 1 https://gitee.com/mirrors/dirsearch.git /app/thirdparty/dirsearch || true

# SecLists - 改用 wget 下载压缩包
RUN wget -q -O /tmp/SecLists.zip https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip && \
    unzip -q /tmp/SecLists.zip -d /app/thirdparty/ && \
    mv /app/thirdparty/SecLists-master /app/thirdparty/SecLists && \
    rm -f /tmp/SecLists.zip || true

# PayloadsAllTheThings - 改用 wget 下载压缩包
RUN wget -q -O /tmp/PayloadsAllTheThings.zip https://github.com/swisskyrepo/PayloadsAllTheThings/archive/refs/heads/master.zip && \
    unzip -q /tmp/PayloadsAllTheThings.zip -d /app/thirdparty/ && \
    mv /app/thirdparty/PayloadsAllTheThings-master /app/thirdparty/PayloadsAllTheThings && \
    rm -f /tmp/PayloadsAllTheThings.zip || true

# SSRFmap
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /app/thirdparty/SSRFmap || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/swisskyrepo/SSRFmap.git /app/thirdparty/SSRFmap || true

# Gopherus
RUN git clone --depth 1 https://github.com/tarunkant/Gopherus.git /app/thirdparty/Gopherus || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/tarunkant/Gopherus.git /app/thirdparty/Gopherus || true

# phpggc
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /app/thirdparty/phpggc || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/ambionics/phpggc.git /app/thirdparty/phpggc || true

# jwt_tool
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /app/thirdparty/jwt_tool || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/ticarpi/jwt_tool.git /app/thirdparty/jwt_tool || true

# JSFinder
RUN git clone --depth 1 https://github.com/Threezh1/JSFinder.git /app/thirdparty/jsfinder || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/Threezh1/JSFinder.git /app/thirdparty/jsfinder || true

# XXEinjector
RUN git clone --depth 1 https://github.com/enjoiz/XXEinjector.git /app/thirdparty/xxe-injector || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/enjoiz/XXEinjector.git /app/thirdparty/xxe-injector || true

# php_filter_chain_generator
RUN git clone --depth 1 https://github.com/synacktiv/php_filter_chain_generator.git /app/thirdparty/php_filter_chain || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/synacktiv/php_filter_chain_generator.git /app/thirdparty/php_filter_chain || true

# ADCollector
RUN git clone --depth 1 https://github.com/leechristensen/ADCollector.git /app/thirdparty/adcollector || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/leechristensen/ADCollector.git /app/thirdparty/adcollector || true

# PetitPotam
RUN git clone --depth 1 https://github.com/topotam/PetitPotam.git /app/thirdparty/PetitPotam || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/topotam/PetitPotam.git /app/thirdparty/PetitPotam || true

# Ghostcat (AJP Shooter)
RUN git clone --depth 1 https://github.com/00theway/Ghostcat-CNVD-2020-10487.git /app/thirdparty/ajpshooter || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/00theway/Ghostcat-CNVD-2020-10487.git /app/thirdparty/ajpshooter || true

# marshalsec
RUN git clone --depth 1 https://github.com/mbechler/marshalsec.git /app/thirdparty/marshalsec || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/mbechler/marshalsec.git /app/thirdparty/marshalsec || true

# fscan
RUN git clone --depth 1 https://github.com/shadow1ng/fscan.git /app/thirdparty/fscan || \
    git clone --depth 1 https://moeyy.cn/gh-proxy/https://github.com/shadow1ng/fscan.git /app/thirdparty/fscan || true

# marshalsec 编译
RUN cd /app/thirdparty/marshalsec && mvn package -DskipTests 2>/dev/null && cp target/marshalsec-*.jar /app/thirdparty/marshalsec.jar || true

# fscan 编译
RUN cd /app/thirdparty/fscan && go build -o /usr/local/bin/fscan . || true

# 下载 jar 文件（使用 moeyy.cn 文件加速）
RUN wget -q -O /app/thirdparty/ysoserial.jar https://moeyy.cn/gh-proxy/https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar || \
    wget -q -O /app/thirdparty/ysoserial.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar || true

RUN wget -q -O /app/thirdparty/JNDIExploit.jar https://moeyy.cn/gh-proxy/https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar || \
    wget -q -O /app/thirdparty/JNDIExploit.jar https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar || true

# frp
RUN wget -q https://moeyy.cn/gh-proxy/https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz && \
    tar -xzf frp_0.52.3_linux_amd64.tar.gz -C /opt/frp --strip-components=1 && \
    rm -f frp_0.52.3_linux_amd64.tar.gz || true

# Windows 工具
RUN wget -q -O /opt/tools/windows/fscan.exe https://moeyy.cn/gh-proxy/https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan.exe || \
    wget -q -O /opt/tools/windows/fscan.exe https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan.exe || true

RUN wget -q -O /opt/tools/potato/PrintSpoofer64.exe https://moeyy.cn/gh-proxy/https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe || \
    wget -q -O /opt/tools/potato/PrintSpoofer64.exe https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe || true

RUN wget -q -O /opt/tools/potato/GodPotato.exe https://moeyy.cn/gh-proxy/https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato_Net40.exe || \
    wget -q -O /opt/tools/potato/GodPotato.exe https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato_Net40.exe || true

RUN wget -q -O /opt/tools/windows/Rubeus.exe https://moeyy.cn/gh-proxy/https://github.com/GhostPack/Rubeus/releases/download/2.2.0/Rubeus.exe || \
    wget -q -O /opt/tools/windows/Rubeus.exe https://github.com/GhostPack/Rubeus/releases/download/2.2.0/Rubeus.exe || true

# mimikatz（Windows）
RUN wget -q -O /tmp/mimikatz.zip https://moeyy.cn/gh-proxy/https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip && \
    unzip -o /tmp/mimikatz.zip -d /opt/tools/windows/mimikatz_temp/ && \
    mv /opt/tools/windows/mimikatz_temp/x64/mimikatz.exe /opt/tools/windows/mimikatz.exe && \
    rm -rf /tmp/mimikatz.zip /opt/tools/windows/mimikatz_temp && \
    chmod +x /opt/tools/windows/mimikatz.exe || true

# xray
RUN wget -q -O /tmp/xray.zip https://moeyy.cn/gh-proxy/https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip && \
    unzip -o /tmp/xray.zip -d /tmp/xray && \
    mv /tmp/xray/xray_linux_amd64 /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray* || true

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