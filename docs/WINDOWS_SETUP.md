# CTF-Agent 2.0 Windows 本地开发环境配置教程

## 目录

1. [环境要求](#环境要求)
2. [安装步骤](#安装步骤)
3. [配置说明](#配置说明)
4. [启动服务](#启动服务)
5. [常见问题](#常见问题)

---

## 环境要求

| 软件 | 版本要求 | 用途 |
|------|---------|------|
| Python | 3.11+ | 后端运行环境 |
| Node.js | 18+ | 前端构建 |
| Git | 最新版 | 代码管理 |
| Docker Desktop | 最新版 | 工具容器（可选） |

---

## 安装步骤

### 1. 克隆项目

```powershell
git clone https://github.com/your-repo/ctf-agent.git
cd ctf-agent
```

### 2. Python环境配置

#### 2.1 创建虚拟环境

```powershell
# 在项目根目录
python -m venv venv

# 激活虚拟环境
.\venv\Scripts\Activate.ps1

# 如果遇到权限问题，先执行：
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 2.2 安装Python依赖

```powershell
# 激活虚拟环境后
pip install -r requirements.txt

# 如果网络慢，使用国内镜像：
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
```

### 3. Node.js环境配置

#### 3.1 安装前端依赖

```powershell
# 进入前端目录
cd frontend

# 安装依赖
npm install

# 如果网络慢，使用国内镜像：
npm install --registry=https://registry.npmmirror.com
```

#### 3.2 配置前端环境变量

前端已创建 `.env.local` 文件，内容如下：

```env
VITE_WS_URL=ws://localhost:8000/ws
```

### 4. Docker配置（可选）

#### 4.1 安装Docker Desktop

1. 下载 [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
2. 安装并启动Docker Desktop
3. 确保Docker正常运行：`docker --version`

#### 4.2 构建工具镜像

```powershell
# 在项目根目录
docker build -t ctf-tools:latest -f docker/all-in-one/Dockerfile .
```

---

## 配置说明

### 1. API配置

创建 `config.yaml` 文件：

```powershell
# 复制示例配置
copy config.yaml.example config.yaml
```

编辑 `config.yaml`：

```yaml
# CTF-Agent Configuration
LLM_API_KEY: "your-api-key-here"
LLM_BASE_URL: "https://api.deepseek.com/v1"
LLM_MODEL: "deepseek-chat"

# Network Configuration
LOCAL_PUBLIC_IP: ""

# Docker Configuration
DOCKER_ENABLED: true
DOCKER_FALLBACK_TO_LOCAL: true
```

### 2. 支持的LLM服务商

| 服务商 | BASE_URL | 模型 |
|--------|----------|------|
| DeepSeek | https://api.deepseek.com/v1 | deepseek-chat, deepseek-reasoner |
| 阿里云DashScope | https://coding.dashscope.aliyuncs.com/v1 | qwen-plus, qwen-turbo, qwen-max |
| OpenAI | https://api.openai.com/v1 | gpt-4o, gpt-4-turbo |
| 智谱 | https://open.bigmodel.cn/api/paas/v4 | glm-4 |

---

## 启动服务

### 方式一：完整启动（推荐）

#### 步骤1：启动后端服务

```powershell
# 确保在项目根目录，虚拟环境已激活
.\venv\Scripts\Activate.ps1

# 启动后端服务
python -m app.server
```

后端服务将在 `http://localhost:8000` 启动。

#### 步骤2：启动前端开发服务器（新终端）

```powershell
# 新开一个终端
cd frontend

# 启动开发服务器
npm run dev
```

前端服务将在 `http://localhost:5173` 启动。

#### 步骤3：访问界面

打开浏览器访问：`http://localhost:5173`

### 方式二：生产环境部署

#### 步骤1：构建前端

```powershell
cd frontend
npm run build
```

构建产物位于 `frontend/dist` 目录。

#### 步骤2：启动后端（自动服务静态文件）

```powershell
python -m app.server
```

访问：`http://localhost:8000`

---

## 常见问题

### Q1: 前端显示 "Disconnected"

**原因**：后端WebSocket服务未启动

**解决方案**：

```powershell
# 确保后端服务正在运行
python -m app.server

# 检查端口是否被占用
netstat -ano | findstr :8000
```

### Q2: Python依赖安装失败

**解决方案**：

```powershell
# 使用国内镜像
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

# 或升级pip后重试
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Q3: npm install 很慢

**解决方案**：

```powershell
# 使用淘宝镜像
npm config set registry https://registry.npmmirror.com
npm install
```

### Q4: Docker构建失败

**解决方案**：

1. 确保Docker Desktop正在运行
2. 检查内存配置（至少分配4GB给Docker）
3. 使用国内镜像源（已在Dockerfile中配置）

### Q5: PowerShell执行策略错误

**错误信息**：`无法加载文件，因为在此系统上禁止运行脚本`

**解决方案**：

```powershell
# 临时允许脚本执行
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Q6: 端口被占用

**解决方案**：

```powershell
# 查找占用端口的进程
netstat -ano | findstr :8000

# 结束进程（替换PID）
taskkill /PID <PID> /F
```

---

## 开发调试

### 后端调试

```powershell
# 启用热重载
uvicorn app.server:app --reload --port 8000
```

### 前端调试

```powershell
cd frontend
npm run dev
```

浏览器访问 `http://localhost:5173`，打开开发者工具查看控制台。

### 查看日志

后端日志会输出到终端，前端日志在浏览器控制台。

---

## 目录结构

```
D:\LangGraph2.0\langGraph\deploy\
├── app/                    # 后端代码
│   ├── server.py           # FastAPI服务器
│   ├── main.py             # Agent主入口
│   ├── settings.py         # 配置管理
│   ├── graph/              # LangGraph图定义
│   ├── agents/             # Agent实现
│   ├── tools_v2/           # 工具系统
│   ├── memory/             # 记忆系统
│   └── coordinator/        # 协调器
├── frontend/               # 前端代码
│   ├── src/                # 源码
│   │   ├── hooks/          # React Hooks
│   │   ├── store/          # Zustand状态
│   │   └── components/     # React组件
│   ├── .env.local          # 环境变量
│   └── package.json        # Node依赖
├── config.yaml             # 运行配置
├── requirements.txt        # Python依赖
└── docker/                 # Docker配置
    └── all-in-one/         # 综合工具镜像
```

---

## 下一步

1. 配置你的API密钥
2. 启动服务
3. 在前端输入目标URL开始自动化攻击

如有问题，请查看 [GitHub Issues](https://github.com/your-repo/ctf-agent/issues)