# CTF-Agent 2.0

基于 **Claude Code Query Loop** 架构的智能CTF自动化求解框架。

**对话式交互，AI自主执行** - 像使用Claude Code一样与AI对话，发布任务后AI自动规划时间并执行。

---

## 核心特性

### Claude Code风格交互
- **对话式界面**: 自然语言描述目标，AI理解并执行
- **自动时间规划**: AI根据任务复杂度动态分配时间预算
- **自主决策执行**: 无需人工干预，AI完全自主决策下一步行动
- **实时状态展示**: 三栏Dashboard显示Timeline/LogStream/DetailPanel
- **打断与恢复**: 随时打断执行，保持控制权

### 架构特点
- **Query Loop**: 替代传统状态机，AI完全自主决策
- **延迟加载**: 工具按需加载，节省Token消耗
- **Memory系统**: Agent间通信，知识积累
- **推测执行**: 预先执行可能操作，节省时间
- **原生工具调用**: 直接调用系统工具，无Docker开销

### 支持的CTF方向
- **Web安全**: SQL注入、XSS、SSRF、RCE...
- **PWN**: 栈溢出、堆利用、ROP...
- **Crypto**: RSA、AES、古典密码...
- **Reverse**: 逆向工程、反编译...
- **Misc**: 隐写、取证、流量分析...
- **内网渗透**: AD域、横向移动...
- **云安全**: 容器逃逸、云服务利用...

---

## 快速开始

### 1. 环境要求

**必需**:
- Python 3.8+
- Node.js 18+ (前端)
- Git

**推荐**:
- Go 1.19+ (安全工具编译)
- Scoop (Windows包管理)

### 2. 安装

**后端**:
```bash
# 克隆项目
git clone https://github.com/your-repo/ctf-agent.git
cd ctf-agent

# 安装Python依赖
pip install -r requirements.txt

# 配置API密钥
cp settings.json.example settings.json
# 编辑settings.json，填入LLM API密钥
```

**前端**:
```bash
cd frontend
npm install
```

**安全工具**:
```bash
# Linux
cd thirdparty
chmod +x install_all.sh
./install_all.sh

# Windows (PowerShell)
cd thirdparty
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install_all.ps1
```

### 3. 运行

**启动后端服务**:
```bash
python -m app.server
# 或
uvicorn app.server:app --host 0.0.0.0 --port 8000
```

**启动前端**:
```bash
cd frontend
npm run dev
```

**访问**: http://localhost:5173

---

## 使用方式

### 对话式交互

在聊天框中输入任务描述，AI会自动理解并执行：

```
用户: 扫描 http://target.com 并找出SQL注入漏洞

AI: 我将开始扫描目标。根据任务复杂度，预计需要15分钟。

[AI自动执行]
→ 信息收集: 端口扫描、目录枚举
→ 漏洞检测: SQL注入测试
→ 漏洞利用: 数据提取
→ Flag获取

[TASK_COMPLETE]
找到Flag: flag{xxx}
```

### CLI使用

```bash
# 基本使用
python -m app.main "扫描 http://target.com"

# 指定类型
python -m app.main "192.168.1.100" --type network

# 详细输出
python -m app.main "http://target.com" -v
```

### 代码调用

```python
from app.main import run_ctf_agent

result = await run_ctf_agent(
    target="http://target.com",
    description="SQL注入测试",
)

print(f"成功: {result['success']}")
print(f"Flags: {result['flags']}")
```

---

## 项目结构

```
CTF-Agent/
├── app/                        # 后端核心
│   ├── core/
│   │   ├── query.py           # Query循环（核心）
│   │   ├── time_manager.py    # 时间管理
│   │   └── speculation.py     # 推测执行
│   ├── tools_v2/              # 工具系统
│   │   ├── native_executor.py # 原生执行器
│   │   ├── tool_factory.py    # 工具工厂
│   │   └── deferred_loader.py # 延迟加载
│   ├── memory/                # Memory系统
│   ├── prompts/               # 提示词
│   └── server.py              # FastAPI服务
│
├── frontend/                   # React前端
│   └── src/
│       ├── components/        # UI组件
│       ├── hooks/             # React Hooks
│       └── store/             # 状态管理
│
├── thirdparty/                 # 第三方工具
│   ├── nmap/                  # 端口扫描
│   ├── nuclei/                # 漏洞扫描
│   ├── sqlmap/                # SQL注入
│   └── ...                    # 更多工具
│
├── docs/                       # 文档
├── skills/                     # Skill定义
└── settings.json              # 配置文件
```

---

## 架构设计

### Query Loop

核心执行流程，完全遵循Claude Code设计：

```
用户输入 → System Prompt → LLM决策 → 工具执行 → 结果处理 → 继续或完成
```

**关键特点**:
- AI完全自主决策下一步
- 无硬编码的阶段转换
- System Prompt指导行为
- 错误直接返回，AI自我纠错

### 时间管理

AI根据任务复杂度自动规划时间：

```python
from app.core.time_manager import TimeManager, TaskType

tm = TimeManager()
budget = tm.create_budget("session-1", TaskType.CTF_SINGLE_FLAG)
# 默认30分钟，AI可在范围内自由分配
```

### 工具调用机制

原生执行，无Docker开销：

```python
from app.tools_v2.native_executor import get_native_executor

executor = get_native_executor()
result = await executor.execute(
    tool_name="nmap",
    args=["-sV", "192.168.1.1"],
    timeout=120000
)
```

---

## 配置

### settings.json

```json
{
  "model": {
    "name": "glm-5",
    "base_url": "https://open.bigmodel.cn/api/paas/v4/",
    "api_key": "${LLM_API_KEY}"
  },
  "timeouts": {
    "ctf_single": 1800,
    "ctf_multi": 3600
  },
  "tools": {
    "native_execution": true
  }
}
```

### 环境变量

```bash
# Linux/macOS
export LLM_API_KEY="your-api-key"

# Windows
set LLM_API_KEY=your-api-key
```

---

## 工具列表

### 核心工具（P0）

| 工具 | 用途 | 安装 |
|------|------|------|
| nmap | 端口扫描 | apt/scoop |
| nuclei | 漏洞扫描 | go install |
| httpx | HTTP探测 | go install |
| sqlmap | SQL注入 | pip install |
| ffuf | 模糊测试 | go install |

### 完整工具列表

见 [thirdparty/README.md](thirdparty/README.md)

---

## 文档

- [Windows安装指南](docs/INSTALL_WINDOWS.md)
- [Linux配置指南](docs/INSTALL_LINUX.md)
- [架构设计](docs/ARCHITECTURE.md)
- [API文档](docs/API.md)

---

## 开发

### 运行测试

```bash
pytest tests/ -v
```

### 代码检查

```bash
semgrep --config=auto app/
```

### 添加新工具

1. 在 `thirdparty/` 创建工具目录
2. 添加安装脚本 `install.sh` 和 `install.ps1`
3. 在 `app/tools_v2/ctf_tools.py` 注册工具Schema

---

## 许可证

MIT License

---

## 贡献

欢迎提交 Issue 和 Pull Request！