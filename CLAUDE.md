# CTF-Agent 2.0 项目文档

## 项目概述

CTF-Agent 是一个基于 **Claude Code 架构** 的智能 CTF 自动化求解框架，实现 AI 完全自主决策攻击。

**核心原则**: 框架做得越少越好，AI做得越多越好

**版本**: 2.0
**架构**: Claude Code Query Loop + MCP Client + OpenSpace Skill Engine

---

## 架构设计

### 1. Query 循环（核心）

极简消息循环，AI完全自主：

```
┌─────────────────────────────────────────────────────┐
│                   Query Loop                         │
│                                                      │
│   while not done:                                    │
│       response = llm.chat(messages, tools)           │
│       if has_tool_calls(response):                   │
│           results = execute_tools(tool_calls)        │
│           messages.append(results)                   │
│       else:                                          │
│           done = True                                │
│                                                      │
│   框架仅干预2件事：                                   │
│     1. 超时熔断（注入[TIMEOUT]消息）                  │
│     2. 循环检测（注入[LOOP_DETECTED]消息）            │
└─────────────────────────────────────────────────────┘
```

### 2. MCP 客户端架构

采用 Claude Code 的 MCP 实现模式：

```
Client → Session → Connector → ConnectionManager → MCP SDK
```

**关键组件**:

| 组件 | 文件 | 职责 |
|------|------|------|
| MCPClient | `mcp/client.py` | 多服务器管理 |
| MCPSession | `mcp/client.py` | 单服务器连接 |
| MCPConnector | `mcp/client.py` | ClientSession包装 |
| MCPConnectionManager | `mcp/client.py` | 任务隔离的async context |

### 3. 工具注册流程

```
启动时:
1. ensure_mcp_tools_registered() → 连接18个MCP服务器（包含OpenSpace）
2. tool_schemas = client.get_all_tool_schemas() → 获取所有工具schema
3. AI自主决定调用哪个工具
```

---

## 工具清单

### MCP工具服务器（18个）

| 服务器 | 工具 | 用途 |
|------|------|------|
| **ctf-basic** | http_request, bash, remember, recall | 基础工具 |
| **ctf-web** | sqlmap, ffuf | Web安全 |
| **ctf-web-advanced** | dirsearch, jwt_tool, gopherus, ssrfmap, xxeinjector, jsfinder, githacker, ghostcat | Web高级 |
| **ctf-recon** | nmap, nuclei | 信息收集 |
| **ctf-internal** | fscan, frp, proxy_chain | 内网渗透 |
| **ctf-ad** | bloodhound, petitpotam, rubeus | AD域攻击 |
| **ctf-deserialization** | ysoserial, marshalsec, phpggc | 反序列化 |
| **ctf-cloud** | cloud_storage_check, cloud_metadata | 云安全 |
| **ctf-ai** | ai_probe | AI安全 |
| **ctf-subdomain** | subfinder | 子域名 |
| **ctf-fingerprint** | whatweb | 指纹识别 |
| **ctf-proxy** | xray | 代理扫描 |
| **ctf-oa** | oa_tools | OA系统 |
| **ctf-jndi** | jndiexploit | JNDI利用 |
| **ctf-binary** | binary_tools | 二进制 |
| **ctf-crypto** | crypto_tools | 密码学 |
| **ctf-misc** | misc_tools | 杂项 |
| **openspace** | search_skills, execute_task, fix_skill, upload_skill | Skill系统 |

---

## Skill 系统

### Skill目录

```
skills/
├── web_exploitation.yaml    # Web渗透
├── sqli_mysql.yaml          # MySQL注入
├── rce.yaml                 # 远程代码执行
├── ssrf.yaml                # SSRF攻击
├── internal_network.yaml    # 内网渗透
├── ad-attack.yaml           # AD域攻击
├── container_escape.yaml    # 容器逃逸
├── k8s_security.yaml        # K8s安全
├── ai_model_attack.yaml     # AI模型攻击
└── ... (共65+个skill)
```

### Skill 使用方式

AI在执行任务时：
1. 遇到不熟悉的漏洞类型 → 调用 `openspace__search_skills`
2. 找到相关skill → 按skill指引执行
3. 成功后 → OpenSpace自动提取新skill（DERIVED模式）

### 比赛覆盖

| 赛区 | 覆盖度 | 关键Skill |
|------|--------|-----------|
| 第一赛区：SRC真实场景 | 100% | src_automation, waf_bypass, auto_recon |
| 第二赛区：CVE/云/AI | 100% | cve_database, container_escape, k8s_security, ai_model_attack |
| 第三赛区：多层网络/OA | 100% | oa_exploitation, multi_stage_attack, proxy_chain |
| 第四赛区：域渗透 | 100% | adcs_attack, golden_ticket, forest_trust, laps_attack |

---

## 前端界面

### 功能

- 实时监控AI决策流程
- Stop按钮打断AI执行
- Running状态指示器
- 用户反馈输入（引导AI调整策略）

### 启动方式

```bash
# 方式1: Web界面
双击 start_web.bat
访问 http://localhost:8000

# 方式2: 命令行交互
双击 start_interactive.bat
```

### 交互流程

```
输入目标地址 → Send → AI开始攻击
                  ↓
           观察AI决策
                  ↓
      点击Stop打断 或 输入反馈引导
```

---

## 配置文件

### settings.json

```json
{
  "model": {
    "provider": "openai",
    "name": "glm-5",
    "base_url": "https://open.bigmodel.cn/api/paas/v4/",
    "api_key": "${LLM_API_KEY}",
    "timeout": 120
  },
  
  "timeouts": {
    "ctf_single": 1800,
    "ctf_multi": 3600
  },
  
  "mcp_servers": {
    "openspace": {
      "command": "D:/LangGraph2.0/langGraph/deploy/venv312/Scripts/openspace-mcp.exe",
      "env": {
        "OPENSPACE_HOST_SKILL_DIRS": "D:/LangGraph2.0/langGraph/deploy/skills",
        "OPENSPACE_WORKSPACE": "D:/LangGraph2.0/langGraph/deploy/OpenSpace-main"
      }
    }
  }
}
```

---

## 目录结构

```
app/
├── core/
│   ├── query.py           # Query循环（~120行）
│   ├── loop_detector.py   # 循环检测器
│   └── time_manager.py    # 时间管理
├── tools_v2/
│   └── mcp/
│       └── client.py      # MCP客户端（~300行）
├── prompts/
│   └── ctf_system_prompt.py  # 系统提示词
├── interactive.py         # 交互式模式
└── web_server.py          # Web服务器

mcp_servers/               # MCP服务器（18个）
├── basic_server.py        # 基础工具
├── web_server.py          # Web工具
├── web_advanced_server.py # Web高级工具
├── recon_server.py        # 信息收集
├── internal_server.py     # 内网渗透
├── ad_server.py           # AD域攻击
├── deserialization_server.py  # 反序列化
├── cloud_server.py        # 云安全
├── ai_server.py           # AI安全
├── subdomain_server.py    # 子域名
├── fingerprint_server.py  # 指纹识别
├── proxy_server.py        # 代理扫描
├── oa_server.py           # OA系统
├── jndi_server.py         # JNDI利用
├── binary_server.py       # 二进制
├── crypto_server.py       # 密码学
├── misc_server.py         # 杂项
└── openspace_server.py    # Skill系统

skills/                    # 65+个skill文件
├── web_exploitation.yaml
├── internal_network.yaml
└── ...

frontend/
├── src/
│   ├── components/
│   │   ├── Chat/InputBar.tsx   # 输入框（Stop按钮）
│   │   └── Console/            # 控制台
│   └── hooks/
│       └── useWebSocket.ts     # WebSocket连接
└── dist/                       # 构建产物

settings.json              # 单一配置文件（包含18个MCP服务器配置）
start_web.bat              # Web启动脚本
start_interactive.bat      # 交互式启动脚本
```

---

## 快速开始

### 1. 安装依赖

```bash
# 创建Python 3.12虚拟环境
py -3.12 -m venv venv312
venv312\Scripts\activate
pip install -r requirements.txt

# 安装OpenSpace
pip install -e ./OpenSpace-main
```

### 2. 配置环境变量

```bash
# Windows
set LLM_API_KEY=your_api_key
set OPENSPACE_API_KEY=your_openspace_key  # 可选

# 或在 settings.json 中直接配置
```

### 3. 启动

```bash
# Web界面
双击 start_web.bat
访问 http://localhost:8000

# 或命令行
venv312\Scripts\python -m app.main "http://target.com"
```

---

## 开发规范

### 代码原则

1. **极简主义**: 框架只做管道，智能全在AI
2. **工具自治**: AI自主决定调用哪个工具
3. **超时唯一熔断**: 不干预AI决策，只做超时保护
4. **MCP标准**: 遵循Claude Code的MCP实现模式

### 错误处理

```python
# MCP工具返回格式
# 成功: [TextContent(type="text", text="结果JSON")]
# 失败: [TextContent(type="text", text="Error: 错误信息")]
```

### 安全约束

1. 禁止硬编码敏感信息
2. 命令注入防护
3. 所有工具调用设置超时

---

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | FastAPI + Uvicorn |
| LLM调用 | LiteLLM |
| MCP协议 | mcp (官方Python SDK) |
| 前端 | React + TypeScript + Tailwind CSS |
| WebSocket | fastapi.WebSocket |
| 工具执行 | 原生系统调用 |

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 2.1 | 2026-04-04 | 完全迁移到MCP架构，18个MCP服务器，删除旧工具系统 |
| 2.0 | 2026-04-04 | 集成OpenSpace MCP客户端，实现交互式模式 |
| 1.5 | 2026-04-03 | 迁移到Claude Code架构 |
| 1.0 | 2026-04-01 | 初始版本 |

---

## 相关文档

- [架构迁移设计](docs/superpowers/specs/2026-04-03-claude-code-architecture-migration-design.md)
- [Skill分析记录](SKILL_ANALYSIS.md)
- [比赛API文档](第二届腾讯云黑客杯智能渗透挑战赛API文档.md)