# Linux 配置指南

本文档详细介绍在Linux系统上安装和配置CTF-Agent 2.0。

---

## 系统要求

- Ubuntu 20.04+ / Debian 11+ / Kali Linux 2023+
- Python 3.8+
- Node.js 18+
- Git

---

## 安装步骤

### 1. 安装系统依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    git \
    curl \
    wget \
    build-essential

# Kali Linux (大部分已预装)
sudo apt-get update
sudo apt-get install -y python3-venv nodejs npm
```

### 2. 安装Go (用于编译安全工具)

```bash
# 下载Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# 解压安装
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 配置环境变量
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# 验证
go version
```

### 3. 克隆项目

```bash
git clone https://github.com/your-repo/ctf-agent.git
cd ctf-agent
```

### 4. 安装Python依赖

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 5. 安装前端依赖

```bash
cd frontend
npm install
cd ..
```

### 6. 配置API密钥

```bash
# 方式1: 使用config.yaml（推荐）
cp config.yaml.example config.yaml
nano config.yaml
```

编辑 `config.yaml`：
```yaml
LLM_API_KEY: "your-api-key-here"
LLM_BASE_URL: "https://dashscope.aliyuncs.com/compatible-mode/v1"
LLM_MODEL: "qwen-plus"
```

支持的 LLM 提供商：
| 提供商 | LLM_BASE_URL | LLM_MODEL |
|--------|--------------|-----------|
| 阿里云通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus`, `qwen-turbo`, `qwen-max` |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4/` | `glm-4`, `glm-4-flash` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |

```bash
# 方式2: 使用环境变量
export LLM_API_KEY="your-api-key"
export LLM_BASE_URL="https://dashscope.aliyuncs.com/compatible-mode/v1"
```

### 7. 安装安全工具

#### 一键安装

```bash
cd thirdparty
chmod +x install_all.sh
./install_all.sh
```

#### 手动安装核心工具

```bash
# nmap
sudo apt-get install -y nmap

# nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# ffuf
go install -v github.com/ffuf/ffuf/v2@latest

# sqlmap
pip install sqlmap

# dirsearch
git clone https://github.com/maurosoria/dirsearch.git ~/tools/dirsearch
cd ~/tools/dirsearch
pip install -r requirements.txt
```

### 8. 安装专业工具 (可选)

```bash
# PWN工具
pip install pwntools
pip install ROPgadget

# 密码学工具
pip install pycryptodome
git clone https://github.com/RsaCtfTool/RsaCtfTool.git ~/tools/RsaCtfTool
cd ~/tools/RsaCtfTool
pip install -r requirements.txt

# 内网渗透工具
pip install impacket
pip install bloodhound
```

---

## 运行

### 启动后端

```bash
# 激活虚拟环境
source venv/bin/activate

# 启动服务
python -m app.server

# 或使用uvicorn
uvicorn app.server:app --host 0.0.0.0 --port 8000
```

### 启动前端

```bash
cd frontend
npm run dev
```

---

## 环境检测

```bash
cd thirdparty
chmod +x check_env.sh
./check_env.sh
```

Python检测：

```bash
source venv/bin/activate
python -c "
from app.tools_v2.native_executor import get_native_executor
import asyncio

async def check():
    executor = get_native_executor()
    tools = ['nmap', 'nuclei', 'httpx', 'sqlmap', 'ffuf']
    for tool in tools:
        available = await executor.check_available(tool)
        print(f'{tool}: {\"OK\" if available else \"NOT FOUND\"}')

asyncio.run(check())
"
```

---

## Systemd服务配置

创建系统服务以便后台运行：

```bash
# 创建服务文件
sudo nano /etc/systemd/system/ctf-agent.service
```

内容：
```ini
[Unit]
Description=CTF-Agent 2.0 Backend
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/ctf-agent
Environment="PATH=/path/to/ctf-agent/venv/bin"
ExecStart=/path/to/ctf-agent/venv/bin/python -m app.server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启用服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable ctf-agent
sudo systemctl start ctf-agent
```

---

## 常见问题

### Q: 权限不足

某些工具需要root权限，使用sudo：
```bash
sudo setcap cap_net_raw+ep /usr/bin/nmap
```

### Q: Go工具找不到

确保PATH包含Go路径：
```bash
echo $PATH
# 应包含 /usr/local/go/bin 和 $HOME/go/bin
```

### Q: pip安装慢

使用国内镜像：
```bash
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: npm安装慢

使用淘宝镜像：
```bash
npm config set registry https://registry.npmmirror.com
```

---

## Kali Linux特别说明

Kali Linux预装了大量安全工具，大部分无需额外安装：

```bash
# 已预装的工具
nmap --version
sqlmap --version
gobuster --version
hydra --version
crackmapexec --version
```

只需安装Go工具：
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

---

## 下一步

- 阅读 [README.md](../README.md) 了解使用方式
- 阅读 [Windows安装指南](INSTALL_WINDOWS.md) 了解Windows安装