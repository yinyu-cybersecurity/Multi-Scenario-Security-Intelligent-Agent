# Windows 安装指南

本文档详细介绍在Windows系统上安装和配置CTF-Agent 2.0。

---

## 系统要求

- Windows 10/11
- Python 3.8+
- Node.js 18+
- Git for Windows
- PowerShell 5.1+

---

## 安装步骤

### 1. 安装基础软件

#### Python

```powershell
# 方法1: 使用scoop (推荐)
scoop install python

# 方法2: 从官网下载
# https://www.python.org/downloads/
# 安装时勾选 "Add Python to PATH"
```

验证安装：
```powershell
python --version
pip --version
```

#### Node.js

```powershell
# 使用scoop
scoop install nodejs

# 或从官网下载
# https://nodejs.org/
```

验证安装：
```powershell
node --version
npm --version
```

#### Git

```powershell
# 使用scoop
scoop install git

# 或从官网下载
# https://git-scm.com/download/win
```

### 2. 克隆项目

```powershell
git clone https://github.com/your-repo/ctf-agent.git
cd ctf-agent
```

### 3. 安装Python依赖

```powershell
# 创建虚拟环境 (推荐)
python -m venv venv
.\venv\Scripts\Activate.ps1

# 安装依赖
pip install -r requirements.txt
```

### 4. 安装前端依赖

```powershell
cd frontend
npm install
cd ..
```

### 5. 配置API密钥

```powershell
# 复制配置模板
copy settings.json.example settings.json

# 编辑配置文件
notepad settings.json
```

填入你的LLM API密钥：
```json
{
  "model": {
    "name": "glm-5",
    "base_url": "https://open.bigmodel.cn/api/paas/v4/",
    "api_key": "your-api-key-here"
  }
}
```

### 6. 安装安全工具

#### 使用一键安装脚本

```powershell
cd thirdparty
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install_all.ps1
```

#### 手动安装常用工具

**nmap**:
```powershell
scoop install nmap
```

**Go工具 (nuclei, httpx, ffuf...)**:
```powershell
# 安装Go
scoop install go

# 安装工具
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/ffuf/ffuf/v2@latest

# 添加到PATH
$env:PATH += ";$env:GOPATH\bin"
```

**sqlmap**:
```powershell
pip install sqlmap
```

---

## 运行

### 启动后端

```powershell
# 激活虚拟环境
.\venv\Scripts\Activate.ps1

# 启动服务
python -m app.server
```

后端服务运行在: http://localhost:8000

### 启动前端

```powershell
cd frontend
npm run dev
```

前端服务运行在: http://localhost:5173

---

## 环境检测

运行环境检测脚本验证所有工具：

```powershell
cd thirdparty
# 在Git Bash中运行
bash check_env.sh
```

或使用Python检测：

```powershell
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

## 常见问题

### Q: PowerShell脚本执行权限错误

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Q: Go工具找不到

确保GOPATH已添加到PATH：
```powershell
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$env:GOPATH\bin", "User")
```

### Q: nmap需要Npcap

nmap可能需要Npcap驱动，从 https://npcap.com/ 下载安装。

### Q: 某些工具需要Visual C++运行时

从微软官网下载安装：
https://aka.ms/vs/17/release/vc_redist.x64.exe

---

## 工具目录结构

```
thirdparty/
├── nmap/
│   ├── install.ps1
│   └── check.sh
├── nuclei/
│   ├── install.ps1
│   └── check.sh
└── ...
```

每个工具都有独立的安装脚本，可单独安装。

---

## 下一步

- 阅读 [README.md](../README.md) 了解使用方式
- 阅读 [Linux配置指南](INSTALL_LINUX.md) 了解Linux安装