# CTF-Agent 2.0 项目文档

## 项目概述

CTF-Agent 是一个 **AI 完全自主** 的智能渗透测试框架，专为腾讯云黑客松智能渗透挑战赛设计。

**核心原则**: 框架做得越少越好，AI 做得越多越好
**版本**: 2.1
**架构**: Query Loop + MCP + Skill Engine

---

## 架构设计

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   CLI        │────▶│  Query Loop      │────▶│  LLM (configurable) │
│   --competition    │  (core/query.py) │◀────│  via OpenAI API     │
│   --interactive    │                  │     └─────────────────────┘
└──────────────┘     └────────┬─────────┘
                              │ tool_calls
                              ▼
                     ┌──────────────────┐
                     │  MCP Client      │
                     │  stdio + HTTP    │
                     └────────┬─────────┘
                              │
               ┌──────────────┼──────────────┐
               ▼              ▼              ▼
        ┌────────────┐ ┌───────────┐ ┌──────────────┐
        │ kali_server │ │ skills/   │ │ competition  │
        │ (12 tools)  │ │ (115+)    │ │ MCP (remote) │
        └────────────┘ └───────────┘ └──────────────┘
```

### Query Loop

```
while not done:
    messages = manage_context_window(messages)  # 防溢出
    response = llm.chat(messages, tools)
    if has_tool_calls(response):
        results = execute_tools(tool_calls)     # 可并行
        messages.append(results)
    else:
        done = True

框架仅干预 3 件事：
  1. 超时熔断（注入 [TIMEOUT] 消息）
  2. 循环检测（注入 [LOOP_DETECTED] 消息）
  3. 上下文窗口管理（自动截断历史消息）
```

---

## 快速开始

### 1. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env，填入 LLM_API_KEY 和比赛配置
```

### 2. Docker 启动（推荐）

```bash
# 比赛自动模式（AI 全自主选题、攻击、提交）
./run.sh competition

# 单题攻击
./run.sh http://target.com

# 智能 REPL（推荐，交互式）
./run.sh repl

# 旧版交互模式
./run.sh interactive
```

### 3. Kali 直接运行

```bash
./run_kali.sh competition           # 比赛自动模式
./run_kali.sh http://target.com     # 单题攻击
./run_kali.sh repl                  # 智能 REPL
./run_kali.sh interactive           # 旧版交互
```

### 4. Python 直接运行

```bash
python -m app.cli --competition                    # 比赛自动
python -m app.cli http://target.com                # 单题攻击
python -m app.cli --repl                           # 智能 REPL
python -m app.cli --interactive                    # 旧版交互
```

**注意**: 直接运行 Python 需要先激活虚拟环境或安装依赖：
```bash
# 激活虚拟环境（推荐）
source .venv/bin/activate

# 或安装依赖
pip install -r requirements.txt
```

---

## 比赛模式

比赛模式下 AI 完全自主管理：
1. 获取题目列表 → 分析难度和分值
2. 选择攻击顺序（easy 优先，高分优先）
3. 启动实例 → 获取入口地址
4. 自主攻击 → 找到 FLAG → 立即提交
5. 检查多 FLAG → 继续攻击直到全部找到
6. 停止实例 → 切换下一题
7. 刷新题目列表 → 检查新关卡解锁

### 比赛 API（已集成）

| 操作 | MCP 工具 | HTTP API |
|------|----------|----------|
| 获取题目 | `list_challenges` | `GET /api/challenges` |
| 启动实例 | `start_challenge` | `POST /api/start_challenge` |
| 停止实例 | `stop_challenge` | `POST /api/stop_challenge` |
| 提交 FLAG | `submit_flag` | `POST /api/submit` |
| 查看提示 | `view_hint` | `POST /api/hint`（扣 10%） |

---

## 工具清单

### kali_server.py（MCP 工具服务器）

**基础工具（8个，始终可用）**：

| 工具 | 用途 |
|------|------|
| **bash** | 执行任意 Kali 命令（300+ 安全工具） |
| **http** | HTTP 请求（GET/POST/PUT/DELETE，支持自定义 headers/body） |
| **read** / **write** | 文件读写 |
| **remember** / **recall** | 结构化记忆系统 |
| **search_skills** | 搜索攻击知识库（124 SKILL.md） |
| **read_skill** | 读取完整 skill 内容 |

**比赛工具（5个，需要比赛环境变量）**：

| 工具 | 用途 |
|------|------|
| **list_challenges** | 获取比赛题目列表 |
| **start_challenge** | 启动题目实例 |
| **stop_challenge** | 停止题目实例 |
| **submit_flag** | 提交 FLAG |
| **view_hint** | 查看提示（扣 10% 分） |

比赛工具触发条件：`COMPETITION_SERVER_HOST` 和 `COMPETITION_AGENT_TOKEN` 环境变量

---

## 技能系统

124 个 SKILL.md 知识文件，覆盖：

| 类别 | 数量 | 示例 |
|------|------|------|
| Web 漏洞 | 50+ | sqli, xss, rce, ssrf, ssti, lfi, xxe |
| 内网渗透 | 20+ | lateral movement, privilege escalation |
| OA 系统 | 10+ | 泛微、用友、致远、蓝凌 |
| AD 域攻击 | 10+ | golden ticket, ADCS, constrained delegation |
| 云安全 | 10+ | container escape, K8s, serverless |
| 密码学 | 10+ | RSA, AES, hash cracking |

---

## 配置

### settings.json

```json
{
  "model": {
    "name": "qwen3.5-plus",
    "base_url": "https://coding.dashscope.aliyuncs.com/v1",
    "api_key": "${LLM_API_KEY}",
    "timeout": 120,
    "fallback_models": []
  },
  "timeouts": { "task": 1800, "tool_default": 300 },
  "retry": { "max_retries": 3, "base_delay": 1.0 },
  "competition": {
    "server_host": "${COMPETITION_SERVER_HOST}",
    "agent_token": "${COMPETITION_AGENT_TOKEN}"
  },
  "query": { "max_turns": 200, "context_window_tokens": 120000 },
  "mcp_servers": {
    "kali": { "command": "python3", "args": ["mcp_servers/kali_server.py"] }
  }
}
```

环境变量优先级 > settings.json > 默认值

---

## 目录结构

```
deploy/
├── app/
│   ├── cli.py                 # CLI 入口（single / competition / interactive）
│   ├── interactive.py         # 交互式模式
│   ├── settings.py            # 配置系统（env > json > default）
│   ├── llm_client.py          # LLM 客户端（重试 + fallback）
│   ├── logger.py              # 日志系统
│   ├── core/
│   │   ├── query.py           # Query Loop（上下文管理 + 并行工具）
│   │   ├── loop_detector.py   # 循环检测器
│   │   └── time_manager.py    # 时间管理
│   ├── tools_v2/mcp/
│   │   └── client.py          # MCP 客户端（stdio + HTTP + 重连）
│   ├── prompts/
│   │   └── ctf_system_prompt.py  # 系统提示词
│   └── memory/
│       └── token_stats.py     # Token 统计
├── mcp_servers/
│   └── kali_server.py         # Kali MCP Server（12 工具）
├── skills/                    # 115+ 攻击知识 YAML
├── settings.json              # 配置文件
├── .env.example               # 环境变量模板
├── Dockerfile                 # Kali Docker 镜像
├── docker-compose.yml         # Docker Compose
├── run.sh                     # Docker 启动脚本
└── run_kali.sh                # Kali 直接启动脚本
```

---

## 企业级特性

| 特性 | 说明 |
|------|------|
| **指数退避重试** | LLM 调用失败自动重试（rate limit / 5xx / timeout）|
| **多模型 fallback** | 主模型失败自动切换备用模型 |
| **上下文窗口管理** | 自动截断历史消息，防止 context_length 错误 |
| **并行工具执行** | 多个工具调用并行执行，提升效率 |
| **MCP 自动重连** | 连接断开自动重连（最多 3 次）|
| **比赛限频保护** | 自动控制 API 调用频率（≤3次/秒）|
| **结构化记忆** | 带时间戳和分类的记忆系统 |
| **智能输出截断** | bash/http 输出智能截断，保留头尾 |
| **循环检测升级** | 循环次数越多，警告越强烈 |
| **配置安全** | API key 走环境变量，禁止硬编码 |

---

## 开发规范

1. **极简主义**: 框架只做管道，智能全在 AI
2. **AI 自主**: AI 自己决定工具选择、攻击策略、任务切换
3. **唯一干预**: 超时熔断、循环检测、上下文管理
4. **MCP 标准**: 遵循 Claude Code 的 MCP 实现模式
5. **安全**: 禁止硬编码密钥，命令注入防护，工具超时
