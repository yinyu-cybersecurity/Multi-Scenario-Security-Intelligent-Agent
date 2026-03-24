#!/bin/bash
# CTF-Agent Quick Deploy Script
# Run this on a fresh Ubuntu 22.04 server

set -e

echo "=========================================="
echo "CTF-Agent Quick Deploy Script"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./deploy.sh"
    exit 1
fi

# Install system dependencies
echo "[1/7] Installing system dependencies..."
apt-get update
apt-get install -y \
    python3.11 python3-pip python3-venv \
    git curl wget unzip \
    openjdk-17-jdk maven golang-go \
    ruby php-cli libssl-dev libssh-dev \
    libimage-exiftool-perl binwalk foremost \
    docker.io docker-compose

# Set up Go environment
echo "[2/7] Setting up Go environment..."
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=/root/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

# Install Go security tools
echo "[3/7] Installing Go security tools..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/ffuf/v2@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/tomnomnom/gf@latest
$GOPATH/bin/nuclei -update-templates

# Install Python tools via pipx
echo "[4/7] Installing Python security tools..."
pip3 install pipx
pipx ensurepath
pipx install sqlmap
pipx install fenjing
pipx install flask-unsign
pipx install crackmapexec
pipx install bloodhound-python
pipx install impacket
pipx install pwntools
pipx install ROPgadget
pipx install jwt-tool
pipx install xsstrike

# Install Ruby tools
echo "[5/7] Installing Ruby tools..."
gem install zsteg one_gadget

# Create Python virtual environment
echo "[6/7] Setting up Python environment..."
cd /opt/ctf-agent
python3.11 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p data/tool_outputs data/tool_raw_logs .memory log thirdparty

# Create tool directories (镜像路径，本地部署也需要)
mkdir -p /opt/tools/potato /opt/tools/ad /opt/tools/linux /opt/tools/windows /opt/frp

echo "[7/7] Downloading open-source security tools..."

# ========== 开源安全工具 ==========
# 内网扫描 - fscan
git clone --depth 1 https://github.com/shadow1ng/fscan.git thirdparty/fscan 2>/dev/null || true
cd thirdparty/fscan && go build -o /usr/local/bin/fscan . && cd /opt/ctf-agent || echo "fscan build skipped"

# SSRF工具
git clone --depth 1 https://github.com/In3tinct/See-SURF.git thirdparty/see-surf 2>/dev/null || true

# OA漏洞工具
git clone --depth 1 https://github.com/NS-Sp4ce/SeeyonExploit.git thirdparty/seeyon-exploit 2>/dev/null || true

# Java反序列化
wget -q -O thirdparty/ysoserial.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar 2>/dev/null || true
wget -q -O thirdparty/JNDIExploit.jar https://github.com/exploitblizzard/JNDIExploit/releases/download/v1.0/JNDIExploit.jar 2>/dev/null || true

# PHP反序列化
git clone --depth 1 https://github.com/ambionics/phpggc.git thirdparty/phpggc 2>/dev/null || true

# Payload集合
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git thirdparty/PayloadsAllTheThings 2>/dev/null || true
git clone --depth 1 https://github.com/danielmiessler/SecLists.git thirdparty/SecLists 2>/dev/null || true

# JWT工具
git clone --depth 1 https://github.com/ticarpi/jwt_tool.git thirdparty/jwt_tool 2>/dev/null || true

# frp代理 - Linux版本
wget -q https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_linux_amd64.tar.gz
tar -xzf frp_0.52.3_linux_amd64.tar.gz -C /opt/frp --strip-components=1
rm frp_0.52.3_linux_amd64.tar.gz

# frp代理 - Windows版本
wget -q https://github.com/fatedier/frp/releases/download/v0.52.3/frp_0.52.3_windows_amd64.zip
unzip -q frp_0.52.3_windows_amd64.zip -d /tmp/frp_win
mv /tmp/frp_win/frpc.exe /opt/tools/windows/
mv /tmp/frp_win/frps.exe /opt/tools/windows/
rm -rf frp_0.52.3_windows_amd64.zip /tmp/frp_win

# fscan - Windows版本
wget -q -O /opt/tools/windows/fscan.exe https://github.com/shadow1ng/fscan/releases/download/v1.8.2/fscan.exe 2>/dev/null || true

# Windows提权工具
wget -q -O /opt/tools/potato/PrintSpoofer64.exe \
    "https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe" 2>/dev/null || true
wget -q -O /opt/tools/potato/SweetPotato.exe \
    "https://github.com/CCob/SweetPotato/raw/master/SweetPotato/bin/Release/SweetPotato.exe" 2>/dev/null || true
wget -q -O /opt/tools/potato/GodPotato.exe \
    "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato_Net40.exe" 2>/dev/null || true

# mimikatz
wget -q -O /tmp/mimikatz.zip \
    "https://github.com/gentilkiwi/mimikatz/releases/download/v2.2.0-20220919/mimikatz_trunk.zip" 2>/dev/null
unzip -q /tmp/mimikatz.zip -d /opt/tools/ 2>/dev/null
rm -f /tmp/mimikatz.zip

echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo ""
echo "Open-source tools installed:"
echo "  - nuclei (CVE scanning)"
echo "  - ffuf (Fuzzing)"
echo "  - sqlmap (SQL injection)"
echo "  - ysoserial.jar (Java deserialization)"
echo "  - JNDIExploit.jar (JNDI injection)"
echo "  - phpggc (PHP deserialization)"
echo "  - PayloadsAllTheThings (Payload collection)"
echo "  - SecLists (Security lists)"
echo "  - See-SURF (SSRF scanner)"
echo "  - SeeyonExploit (OA exploits)"
echo ""
echo "Next steps:"
echo "1. Copy config.yaml.example to config.yaml"
echo "2. Edit config.yaml with your API key"
echo "3. Run: python self_check.py"
echo "4. Run: docker-compose up -d"
echo ""