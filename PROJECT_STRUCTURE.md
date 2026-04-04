# CTF-Agent 2.0 项目结构说明

## 项目概述

CTF-Agent 2.0 是一个基于 Claude Code 架构的智能 CTF 自动化求解框架。核心设计理念是 **AI 完全自主决策**，通过 Query 循环实现，而非预制的 DAG 或状态机。

**当前版本**: 2.0
**架构基座**: Claude Code Query Loop + External Store

---

## 目录结构总览

```
D:\LangGraph2.0\langGraph\deploy\
├── app/                      # 核心应用代码
├── frontend/                 # React前端界面
├── skills/                   # Skill知识包定义
├── scripts/                  # 工具脚本
├── docs/                     # 文档
├── thirdparty/               # 第三方工具
├── test_suite/               # 测试套件
├── settings.json             # 单一配置文件
├── CLAUDE.md                 # 项目配置说明
├── README.md                 # 项目说明
└── PROJECT_STRUCTURE.md      # 本文件
```

---

## 核心模块详解

### 1. `app/` - 核心应用代码

```
app/
├── core/                     # 核心模块
│   ├── query.py              # ★ Query循环 - 主入口
│   │   ├── query()           # 异步生成器，返回事件流
│   │   ├── execute_tool_via_registry()  # 工具执行
│   │   ├── _extract_tool_calls_from_text()  # 文本解析工具调用
│   │   └── _get_skill_suggestions()  # Skill推荐
│   │
│   ├── time_manager.py       # 时间管理器（超时熔断）
│   └── speculation.py        # 推测执行（未使用）
│
├── state/                    # 状态管理
│   ├── store.py              # ★ 外部Store - 状态管理核心
│   │   ├── Store<T>          # 通用Store类
│   │   ├── AppState          # 动态状态字典
│   │   ├── set_state()       # 状态更新（引用相等检查）
│   │   └── subscribe()       # 订阅状态变化
│   │
│   └── selector_store.py     # 选择器Store（细粒度订阅）
│
├── skills/                   # Skill系统
│   ├── registry.py           # ★ Skill注册表
│   │   ├── Skill             # Skill数据类
│   │   ├── SkillRegistry     # 注册表
│   │   ├── get_skill_registry()  # 全局单例
│   │   └── find_matching_skills()  # 上下文匹配
│   │
│   └── skill_loader.py       # 延迟加载器（未使用）
│
├── tools_v2/                 # 工具系统V2
│   ├── mcp/
│   │   └── client.py      # ★ MCP客户端（~300行）
│   │
│   └── deferred_loader.py    # 延迟加载器
│   └── concurrency_config.py # 并发配置
│
├── tools_v2/tools/           # 工具实现
│   ├── __init__.py           # 工具模块入口
│   ├── simple_tools.py       # 基础工具
│   │   ├── http_request      # HTTP请求
│   │   ├── bash              # Bash命令
│   │   ├── read/write        # 文件读写
│   │   └── glob/grep         # 搜索工具
│   │
│   ├── specialized_handlers.py  # 专业工具
│   │   ├── nmap_handler      # 端口扫描
│   │   ├── sqlmap_handler    # SQL注入
│   │   ├── nuclei_handler    # 漏洞扫描
│   │   └── ffuf_handler      # 目录枚举
│   │
│   ├── specialized_schemas.py   # 专业工具Schema
│   └── cloud_storage_tester.py  # 云存储测试
│
├── prompts/                  # 提示词系统
│   ├── ctf_system_prompt.py  # ★ Main Agent系统提示词
│   ├── agent_prompts.py      # ★ 各Agent提示词
│   │   ├── EXPLORE_SYSTEM_PROMPT   # Explore Agent
│   │   ├── PLAN_SYSTEM_PROMPT      # Plan Agent
│   │   ├── ATTACK_SYSTEM_PROMPT    # Attack Agent
│   │   ├── VERIFY_SYSTEM_PROMPT    # Verify Agent
│   │   └── COORDINATOR_SYSTEM_PROMPT  # Coordinator
│   │
│   ├── tool_guidance.py      # 工具使用指南
│   ├── error_recovery.py     # 错误恢复提示
│   └── scene_framework.py    # 场景框架（未使用）
│
├── memory/                   # Memory系统
│   ├── agent_memory.py       # ★ Agent Memory
│   │   ├── AgentMemory       # Memory实例
│   │   ├── write_finding()   # 记录发现
│   │   └── get_findings()    # 获取发现
│   │
│   ├── incremental_memory.py # 增量Memory（未使用）
│   ├── context_compressor.py # 上下文压缩
│   ├── prompt_cache.py       # 提示词缓存
│   └── token_stats.py        # Token统计
│
├── agents/                   # Agent定义
│   ├── base.py               # Agent基类
│   │   ├── AgentType         # Agent类型枚举
│   │   └── ToolPermission    # 工具权限枚举
│   │
│   └── autonomous_agent.py   # 自主Agent（未使用）
│
├── coordinator/              # 协调器（未使用）
│   ├── dispatcher.py         # 调度器
│   └── __init__.py
│
├── nodes/                    # 节点（未使用）
├── topology/                 # 拓扑（未使用）
├── capabilities/             # 能力（未使用）
├── compressor/               # 压缩器
├── config/                   # 配置管理
├── reports/                  # 报告生成
│
├── llm_client.py             # ★ LLM客户端
│   └── llm_client            # 支持智谱API的客户端
│
├── logger.py                 # 日志系统
├── settings.py               # 设置加载
├── main.py                   # ★ 主入口
├── server.py                 # WebSocket服务器
├── session_manager.py        # 会话管理
├── self_correction.py        # 自我纠正（未使用）
├── flag_extractor_v2.py      # Flag提取
├── url_utils.py              # URL工具
└── staged_planner.py         # 分阶段规划器（未使用）
```

---

### 2. `frontend/` - React前端界面

```
frontend/
├── src/
│   ├── components/           # React组件
│   │   ├── DecisionFlow/     # ★ 决策流组件（脉冲动画）
│   │   ├── LogStream.tsx     # 日志流显示
│   │   ├── ChatInterface.tsx # 聊天界面
│   │   └── ...
│   │
│   ├── hooks/                # React Hooks
│   │   ├── useWebSocket.ts   # ★ WebSocket连接
│   │   ├── useDecisionFlow.ts # 决策流Hook
│   │   └── ...
│   │
│   ├── store/                # 状态管理
│   │   ├── types.ts          # 类型定义
│   │   └── ...
│   │
│   ├── App.tsx               # 主应用组件
│   ├── main.tsx              # 入口文件
│   └── index.css             # 全局样式
│
├── package.json              # 依赖配置
├── vite.config.ts            # Vite配置
└── tsconfig.json             # TypeScript配置
```

---

### 3. `skills/` - Skill知识包定义

```
skills/
├── meta_skill_selector.yaml  # ★ Meta Skill - 场景选择器
├── sqli_skill.yaml           # SQL注入Skill
├── upload_skill.yaml         # 文件上传Skill
├── ssrf_skill.yaml           # SSRF Skill
├── rce_skill.yaml            # RCE Skill
├── xxe_skill.yaml            # XXE Skill
├── ssti_skill.yaml           # SSTI Skill
├── lfi_skill.yaml            # LFI Skill
├── auth_bypass_skill.yaml    # 认证绕过Skill
├── crypto_skill.yaml         # 密码学Skill
├── pwn_skill.yaml            # Pwn Skill
├── reverse_skill.yaml        # 逆向Skill
├── misc_skill.yaml           # Misc Skill
├── intranet_skill.yaml       # 内网渗透Skill
├── cloud_skill.yaml          # 云安全Skill
└── ai_security_skill.yaml    # AI安全Skill
```

**Skill文件结构：**

```yaml
name: SQL注入攻击
description: SQL注入漏洞发现与利用
domain: web
knowledge: |
  # SQL注入知识...
workflows:
  - name: 标准注入流程
    steps:
      - description: 测试注入点
        suggested_tools: [http_request]
      - description: 数据提取
        suggested_tools: [sqlmap]
tool_preferences:
  http_request: { score: 0.9, reason: "快速测试" }
  sqlmap: { score: 0.8, reason: "自动化利用" }
examples:
  - scenario: 登录绕过
    solution: "' OR 1=1--"
    tools_used: [http_request]
```

---

### 4. `docs/` - 文档目录

```
docs/
├── REVIEW_REQUEST.md         # ★ 架构审查请求
├── ROADMAP.md                # 项目路线图
├── API_DOCUMENTATION.md      # API文档
├── USAGE.md                  # 使用指南
├── CONTRIBUTING.md           # 贡献指南
├── DEPLOYMENT.md             # 部署指南
├── INSTALL_WINDOWS.md        # Windows安装
├── INSTALL_LINUX.md          # Linux安装
├── FRONTEND_DESIGN.md        # 前端设计
│
├── superpowers/              # 设计文档
│   ├── Claude_Code核心设计与CTF-Agent改进研究报告.md
│   ├── specs/
│   │   └── 2026-04-03-claude-code-architecture-migration-design.md
│   └── plans/
│       └── 2026-04-03-claude-code-architecture-migration-plan.md
│
└── archive/                  # 归档文档
    ├── legacy_docs/          # 旧文档
    ├── fix_reports/          # 修复报告
    └── old_designs/          # 旧设计文档
```

---

### 5. `thirdparty/` - 第三方工具

```
thirdparty/
├── nuclei/                   # 漏洞扫描
├── ffuf/                     # 目录枚举
├── httpx/                    # HTTP探测
├── subfinder/                # 子域名发现
├── ssrfmap/                  # SSRF利用
├── gopherus/                 # Gopher构造
├── jwt_tool/                 # JWT利用
├── jsfinder/                 # JS发现
├── xxeinjector/              # XXE注入
├── php_filter_chain_generator/  # PHP链生成
├── petitpotam/               # PetitPotam
└── ghostcat/                 # Ghostcat
```

---

### 6. `scripts/` - 工具脚本

```
scripts/
└── install_tools.sh          # 工具安装脚本
```

---

### 7. `test_suite/` - 测试套件

```
test_suite/
└── TEST_PLAN.md              # 测试计划
```

---

## 核心配置文件

### `settings.json` - 单一配置文件

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

### `CLAUDE.md` - 项目配置说明

包含：
- 项目概述
- 核心架构说明
- 工具框架说明
- MCP插件配置
- 代码规范
- 目录结构
- 开发指南

---

## 关键数据流

### Query循环数据流

```
用户输入
    ↓
[Query循环] ─────────────────────────────
    │
    ├─→ 动态获取工具Schema (deferred_loader)
    │
    ├─→ Skill推荐 (skill_suggestions)
    │
    ├─→ LLM调用 (llm_client)
    │       ↓
    │   AI响应 (content + tool_calls)
    │
    ├─→ 工具调用处理
    │       ↓
    │   execute_tool_via_registry()
    │       ↓
    │   工具执行结果 → Memory记录
    │       ↓
    │   结果返回LLM
    │
    ├─→ 完成检测 ([TASK_COMPLETE])
    │
    └─→ 下一轮循环 ──────────────────────
```

### 状态管理数据流

```
外部Store
    │
    ├─→ set_state(updater)
    │       ↓
    │   引用相等检查
    │       ↓
    │   状态更新
    │       ↓
    │   触发订阅
    │
    └─→ subscribe(listener)
            ↓
        返回取消函数
```

### Skill系统数据流

```
YAML文件
    ↓
Skill.from_yaml()
    ↓
SkillRegistry.register()
    ↓
find_matching_skills(context)
    ↓
工具推荐 + 工作流建议
    ↓
注入到Query循环
```

---

## 模块依赖关系

```
main.py
    │
    ├── query.py (核心循环)
    │       │
    │       ├── llm_client.py (LLM调用)
    │       ├── tool_factory.py (工具工厂)
    │       ├── registry.py (Skill系统)
    │       ├── store.py (状态管理)
    │       └── agent_memory.py (Memory系统)
    │
    ├── server.py (WebSocket服务)
    │       └── session_manager.py
    │
    └── settings.py (配置加载)
```

---

## 未使用/部分实现的模块

| 模块 | 文件路径 | 状态 |
|------|---------|------|
| 时间管理器 | `app/core/time_manager.py` | 已实现，未集成到Query循环 |
| 选择器Store | `app/state/selector_store.py` | 已实现，未使用 |
| Skill延迟加载 | `app/skills/skill_loader.py` | 已实现，未使用 |
| 工具延迟加载 | `app/tools_v2/deferred_loader.py` | 已实现，Query循环未有效利用 |
| 自主Agent | `app/agents/autonomous_agent.py` | 已实现，未使用 |
| 协调器 | `app/coordinator/dispatcher.py` | 已实现，未使用 |
| 分阶段规划器 | `app/staged_planner.py` | 已实现，未使用 |
| 自我纠正 | `app/self_correction.py` | 已实现，未使用 |
| 增量Memory | `app/memory/incremental_memory.py` | 已实现，未使用 |

---

## 测试文件

```
test_framework.py             # ★ 框架综合测试
test_prompt_fix.py            # ★ 提示词验证测试
test_tool_flow.py             # 工具流程测试
```

---

## 开发指南

### 启动后端

```bash
# 命令行模式
python -m app.main "http://target.com"

# 服务器模式
python -m app.main --server
```

### 启动前端

```bash
cd frontend
npm install
npm run dev
```

### 运行测试

```bash
# 框架测试
python test_framework.py

# 提示词测试
python test_prompt_fix.py
```

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 2.0 | 2026-04-03 | 完全迁移到Claude Code架构，企业级提示词优化 |
| 1.0 | 2026-03-01 | 初始版本，LangGraph架构 |

---

## 相关链接

- [Claude Code架构设计](docs/superpowers/specs/2026-04-03-claude-code-architecture-migration-design.md)
- [架构审查请求](docs/REVIEW_REQUEST.md)
- [使用指南](docs/USAGE.md)
- [API文档](docs/API_DOCUMENTATION.md)