# CTF-Agent 2.0

AI 自主渗透测试框架 — 双 Agent 协作 · 知识驱动 · 完全自主

---

## 设计理念

> **框架做得越少越好，AI 做得越多越好。**

这不是一个"编排工具调用"的框架。它的核心思想是：框架只负责消息传递和基础保障，所有决策都由 LLM 自主做出。

框架只干预 3 件事：

1. **超时熔断** — 防止单题卡死
2. **循环检测** — 防止重复相同操作
3. **上下文窗口管理** — 防止 token 溢出

其余一切 — 选什么工具、攻击什么目标、什么时候切换任务 — 全部由 AI 决定。

---

## 快速开始

### 前置条件

- Python 3.10+ 或 Docker
- LLM API Key（推荐 Qwen3.6-plus）
- 可选：Kali Linux（直接运行需要）

### 方式一：Kali 直接运行（推荐）

```bash
git clone <repo-url>
cd ctf-agent/deploy
cp .env.example .env
# 编辑 .env，填入 LLM_API_KEY
chmod +x run_kali.sh
./run_kali.sh http://target.com
```

### 方式二：Docker

```bash
./run.sh http://target.com
```

### 方式三：Python 直接运行

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.cli http://target.com
```

更多运行模式见下方[运行模式](#运行模式)章节。

---

## 双 Agent 协作架构

这是框架最独特的设计。系统中有两个 Agent：

- **Operator**（主 Agent）— 执行渗透测试，调用工具，发现漏洞，提交 FLAG
- **Advisor**（顾问 Agent）— 独立评估 Operator 的思维质量，必要时注入指导意见

两者通过消息系统协作，Advisor 不直接控制 Operator，而是通过 `[GUIDANCE]` 消息影响其后续决策。

```
┌────────────────────────────────────────────────────────────┐
│                   双 Agent 协作                              │
│                                                            │
│  ┌──────────────────┐         ┌────────────────────────┐  │
│  │  Operator Agent  │         │   Advisor Agent        │  │
│  │  (主攻击 Agent)   │         │   (独立评估 Agent)      │  │
│  │                  │         │                        │  │
│  │ • 执行渗透测试    │         │ • 每 3 轮评估思维质量   │  │
│  │ • 调用 MCP 工具   │         │ • 注入 GUIDANCE 指导    │  │
│  │ • 自主决策策略    │         │ • 语义压缩对话历史      │  │
│  │ • 发现并提交 FLAG │         │ • 后台侦察 + 阶段预测   │  │
│  └────────┬─────────┘         └────────────┬───────────┘  │
│           │                                │               │
│           │  tool_calls + thinking         │  每 3 轮       │
│           │                                ▼               │
│           │                       ┌──────────────┐         │
│           │                       │  evaluate()  │         │
│           │                       │  LLM 评估     │         │
│           │                       └──────┬───────┘         │
│           │              need_intervention?                 │
│           │              ┌──────┴───────┐                  │
│           │             YES             NO                 │
│           │              │               │                  │
│           │              ▼               │                  │
│           │     [GUIDANCE] 注入          │                  │
│           │     "你忽略了XX线索..."       │                  │
│           │              │               │                  │
│           │              ▼               ▼                  │
│           │       下一轮 LLM 收到 GUIDANCE                   │
│           └───────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

Advisor 有三种能力，分别展开说明。

### 能力 1：evaluate() — 思维质量评估

每 3 轮调用 LLM 评估 Operator 的思考质量，返回 JSON 格式的评估结果：

```json
{
  "need_intervention": true,
  "reason": "Operator 在 80 端口反复尝试相同的目录扫描",
  "guidance": "80 端口已尝试多种路径扫描均无果，建议换方向。nmap 显示 Apache 2.4.49 存在 CVE-2021-41773，是否尝试过 path traversal？",
  "predicted_next_steps": ["CVE-2021-41773 path traversal", "nuclei 扫描其他端口"],
  "unaddressed_guidance": ["之前建议的 nuclei 全局扫描仍未执行"]
}
```

评估分 6 个攻击阶段，每个阶段有独立的评估标准：

| 阶段 | 关注点 |
|------|--------|
| recon | 扫描覆盖面、效率、是否遗漏关键信息 |
| vuln_discovery | 是否找到攻击面、工具选择是否合理 |
| vuln_exploit | 利用方法是否正确、失败后是否有预案 |
| privesc | 提权路径是否清晰、权限枚举是否全面 |
| lateral | 横向移动策略、内网侦察是否充分 |
| objective | 目标是否明确、FLAG 获取策略是否有效 |

如果 Advisor 认为需要干预，会注入 `[GUIDANCE]` 消息到对话中。Operator 在下一轮 LLM 调用时会收到这条消息，并据此调整策略。

### 能力 2：compress_conversation() — 语义压缩

当对话达到 15 轮或超过 300K tokens 时触发。不是简单截断，而是让 LLM 提取关键事实：

- 保留：凭据、端点、漏洞路径、已尝试的方法
- 丢弃：冗余的工具输出、重复的对话

压缩后的摘要会注入到对话中，Operator 可以基于摘要恢复上下文。

### 能力 3：后台侦察循环 + 阶段预测

这是 Advisor 最独特的设计 — **不是被动评估，而是主动预测下一阶段需要什么知识，提前侦察好**。

```
┌──────────────────────────────────────────────────────┐
│              Advisor 后台侦察循环                      │
│                                                      │
│  评估当前阶段 → 预测下一阶段 → 判断是否需要侦察        │
│       ↓                                               │
│  后台 search_skills(query) → 缓存结果                 │
│       ↓                                               │
│  下一轮验证预测：                                     │
│    correct → 注入 [RECON] 消息到 Operator 对话         │
│    changed → 取消侦察，重新预测                       │
│                                                      │
│  各挑战的缓存隔离，策略变化时自动取消                   │
└──────────────────────────────────────────────────────┘
```

具体流程：

1. Advisor 评估 Operator 当前行为，判断处于哪个攻击阶段（如 recon）
2. 预测下一阶段（如 vuln_discovery），判断是否需要提前搜索相关技能
3. 如果需要，后台异步调用 `search_skills("vuln discovery web")`
4. 结果缓存到 `_recon_cache[challenge_code][stage]`
5. 下一轮评估时验证预测是否正确：
   - `correct` / `confirmed`：Operator 确实进入了预测的阶段，将缓存的技能知识以 `[RECON]` 消息注入对话
   - `changed`：Operator 换了方向，取消正在进行的侦察任务
6. Operator 进入新阶段时，已经有相关知识准备，不用从零搜索

实际运行示例：

```
Turn 1-3:  Operator 做 recon（端口扫描）
           Advisor 评估: current_stage=recon, predicted_next=vuln_discovery
           → 需要侦察 → 后台 search_skills("vuln discovery web")

Turn 4-6:  Operator 开始找漏洞
           Advisor 验证: prediction_match="correct" ✓
           → 注入 [RECON] vuln_discovery 阶段资源
           → Operator 立即看到相关技能知识
           → 新一轮评估: current_stage=vuln_discovery
           → 预测下一阶段: vuln_exploit → 开始新一轮侦察
```

### 未决建议追踪

Advisor 会记住自己给出的历史建议，在每次评估时检查 Operator 是否采纳。未采纳的建议保留在 `unaddressed_guidance` 列表中，下次评估时再次检查。这形成了一个持续的指导闭环，避免 Advisor 的建议被忽略后就不再提及。

---

## Query Loop 核心循环

Query Loop 是框架的核心引擎（`app/core/query.py`）。它的逻辑很简单：

```
while not done:
    1. manage_context_window(messages)   # 分级截断，防止溢出
    2. response = llm.call(messages)     # LLM 完全自主决策
    3. if has_tool_calls:
         并行执行工具 → 结果追加到 messages
       else:
         done = True  # AI 认为任务完成
    4. 每 3 轮: Advisor 评估思维质量
    5. 每 15 轮: Token 统计注入
    6. 每 15 分钟: 时间盒反思
    7. 需要时: 语义压缩
```

框架不决定选什么工具、攻击什么目标，只是保证：

- 消息不丢失（上下文管理）
- 不会无限循环（循环检测）
- 不会永远卡住（超时熔断）
- Advisor 能监督（定期评估）

---

## 三级思考链

系统提示词要求 LLM 在每次工具调用前输出结构化思考：

```
【当前状态】我已经做了什么，发现了什么
【下一步目标】接下来要解决什么问题
【行动方案】具体用什么工具/方法
【失败预案】如果失败了换什么方向
```

这不是装饰性的。它确保了：

- 思维可审计 — 每次决策都有记录
- 策略可追踪 — 知道为什么选这个工具
- 失败可恢复 — 有预设的 B 计划

Advisor 在评估时会阅读这些思考，判断 Operator 的方向是否正确。

---

## 技能系统

框架内置 150 个 SKILL.md 攻击技能文件。Operator 遇到问题时不是盲目尝试，而是先搜索相关知识：

```
Operator 发现 SSTI 漏洞
  → search_skills("ssti flask jinja2")
    → TF-IDF 匹配，返回相关技能
    → ssti-attack-chain, ssti-ssti-detail, flask-session
  → read_skill("ssti-attack-chain")
    → 获取完整的攻击流程、工具参数、绕过技巧
  → 按照 SKILL 指导执行攻击
```

### 技能分类

| 类别 | 数量 | 代表技能 |
|------|------|---------|
| Web 漏洞 | 40+ | sqli, xss, rce, ssrf, ssti, lfi, xxe |
| SQL 注入专项 | 15+ | union, blind, time, error-based, waf-bypass |
| 内网/AD 域 | 15+ | golden-ticket, ADCS, kerberoasting, laps |
| 反序列化 | 5+ | java-deserialization, php-deserialization, pickle |
| 框架专项 | 5+ | flask-session, spring-actuator, tomcat |
| 云/容器安全 | 5+ | container-escape, k8s-security, serverless |
| AI 安全 | 5+ | rag-attack, ai-agent-security, tempest |
| 密码学/取证 | 5+ | crypto-exploitation, windows-forensics |
| 隧道/代理 | 5+ | tunnel, proxy-chain, network-pivoting |
| WAF 绕过 | 5+ | 各漏洞类型的 WAF Bypass 专项 |

### 搜索策略

`search_skills` 使用三级降级搜索：

1. **OpenSpace SkillEngine** — TF-IDF + BM25（如果有 OpenSpace 依赖）
2. **本地 TF-IDF** — 自实现倒排索引，名称/描述权重 3x，领域权重 2x
3. **子串匹配** — 目录名模糊匹配兜底

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                     CTF-Agent 2.0                            │
│                                                              │
│  ┌──────────┐     ┌────────────────┐     ┌───────────────┐  │
│  │ CLI      │────▶│  Query Loop    │────▶│  LLM Client   │  │
│  │ 入口     │     │  (消息管道)     │◀────│  httpx async  │  │
│  │          │     │                │     │  + 重试/降级   │  │
│  └──────────┘     └───────┬────────┘     └───────────────┘  │
│                           │ tool_calls                       │
│                    ┌──────▼───────┐                          │
│                    │  MCP Client  │                          │
│                    │  stdio+HTTP  │                          │
│                    └──────┬───────┘                          │
│          ┌────────────────┼────────────────┐                 │
│          ▼                ▼                ▼                 │
│   ┌────────────┐  ┌────────────┐  ┌──────────────┐         │
│   │ kali_server│  │null_zone_  │  │ Competition  │         │
│   │ (17 tools) │  │ forum      │  │ MCP (remote) │         │
│   │            │  │ (22 tools) │  │ (HTTP)       │         │
│   └──────┬─────┘  └────────────┘  └──────────────┘         │
│          │                                                  │
│          ▼                                                  │
│   ┌────────────┐     ┌──────────────────┐                   │
│   │ Skill      │◀────│ Advisor Agent    │                   │
│   │ Engine     │     │ 评估/压缩/侦察    │                   │
│   │ 150 skills │     │ 每 3 轮          │                   │
│   └────────────┘     └──────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

### 组件说明

| 组件 | 文件 | 职责 |
|------|------|------|
| CLI 入口 | `app/cli.py` | 解析命令行参数，选择运行模式 |
| Query Loop | `app/core/query.py` | 核心消息管道，协调 LLM 调用和工具执行 |
| LLM Client | `app/llm_client.py` | httpx 异步调用，指数退避重试，多模型 fallback |
| MCP Client | `app/tools_v2/mcp/client.py` | 统一管理 stdio 和 HTTP 两种 MCP 传输 |
| Kali Server | `mcp_servers/kali_server.py` | 17 个渗透测试工具 |
| Forum Server | `mcp_servers/null_zone_forum.py` | 22 个论坛交互工具 |
| Advisor | `app/advisors/ctf_advisor.py` | 独立评估 Operator，注入指导 |
| Skill Engine | `app/tools_v2/skill_engine.py` | TF-IDF 技能搜索 |
| Loop Detector | `app/core/loop_detector.py` | 滑动窗口循环检测 |
| Settings | `app/settings.py` | 三层配置（env > json > default） |

---

## 运行模式

| 模式 | 启动方式 | 说明 |
|------|---------|------|
| 单题攻击 | `python -m app.cli http://target` | 针对单一目标进行渗透测试 |
| 比赛自动 | `python -m app.cli --competition` | AI 自主选题、攻击、提交 FLAG |
| 智能 REPL | `python -m app.cli --repl` | 交互式模式，可以手动输入指导 |
| 旧版交互 | `python -m app.cli --interactive` | 兼容旧版，支持 run/stop/pause |

---

## MCP 工具参考

### Kali Server（17 个工具）

| 工具 | 参数 | 说明 |
|------|------|------|
| `bash` | command, timeout, background | 执行任意 shell 命令，支持后台模式 |
| `bash_status` | exec_id | 查询后台命令状态 |
| `http` | url, method, headers, body | HTTP 请求（GET/POST/PUT/DELETE） |
| `read` | path, max_size | 读取文件内容 |
| `write` | path, content | 写入文件 |
| `remember` | key, value, category | 存储结构化信息（凭据、端点、漏洞等） |
| `recall` | query | 搜索记忆 |
| `search_skills` | query | 搜索攻击技能知识库 |
| `read_skill` | name | 读取完整技能内容 |
| `create_skill` | name, content | 创建新技能 |
| `update_skill` | name, content | 更新技能 |
| `list_skills` | 无 | 列出所有技能 |
| `list_challenges` | 无 | 获取比赛题目列表（需比赛环境变量） |
| `start_challenge` | code | 启动题目实例 |
| `stop_challenge` | code | 停止题目实例 |
| `submit_flag` | code, flag | 提交 FLAG |
| `view_hint` | code | 查看提示（扣 10% 分数） |

### Null Zone Forum Server（22 个工具）

用于比赛中的论坛交互，包括：帖子浏览/搜索/创建、私信、投票、评论、Agent 信息管理等。

---

## 比赛模式工作流

比赛模式下 AI 完全自主运行：

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ list_        │───▶│ AI 分析难度  │───▶│ 选择攻击顺序  │
│ challenges   │    │ 和分值        │    │ (easy 优先)   │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ start_       │
                                        │ challenge    │
                                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ view_hint     │
                                        │ (强制第一步)   │
                                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ 自主攻击       │
                                        │ 搜索技能       │
                                        │ 执行利用       │
                                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ 发现 FLAG     │
                                        │ submit_flag   │
                                        │ 检查多 FLAG    │
                                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ stop_        │
                                        │ challenge    │
                                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │ 刷新题目列表   │
                                        │ 检查新关卡解锁 │
                                        │ 切换下一题     │
                                        └──────────────┘
```

关键设计：

- `view_hint` 是强制第一步 — 先看 hint 再决定攻击策略，避免盲目攻击
- 最多 3 个并发实例 — 防止资源浪费
- FLAG 自动检测 — `flag{...}` 格式自动识别并提交
- 多 FLAG 检查 — 一个题目可能有多个 FLAG，全部找到才切换

---

## 可靠性设计

| 机制 | 说明 |
|------|------|
| 指数退避重试 | LLM 调用失败自动重试（1s → 2s → 4s，最多 3 次） |
| 多模型 fallback | 主模型失败后依次尝试备用模型 |
| 上下文窗口管理 | 1M token 窗口，分级截断（200K/500K/800K 阈值） |
| 并行工具调用 | 多个工具调用并行执行，同 server 最多 4 并发 |
| MCP 自动重连 | 连接断开自动重连（2s/4s/8s 退避，最多 3 次） |
| 循环检测 | MD5 签名去重，滑动窗口检测，警告逐级升级 |
| Flag 自动检测 | 正则匹配 `flag{...}`，自动提交 |
| 比赛限频 | 比赛 API 请求间隔 0.35s，确保不超频 |

---

## 配置

### 配置优先级

```
环境变量 > settings.json (${VAR} 引用) > settings.json 默认值 > 代码默认值
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `LLM_API_KEY` | LLM API 密钥（必填） | - |
| `LLM_BASE_URL` | API 端点 | DashScope |
| `LLM_MODEL` | 模型名称 | qwen3.6-plus |
| `LLM_TIMEOUT` | 单次调用超时（秒） | 120 |
| `TASK_TIMEOUT` | 任务总超时（秒） | 3600 |
| `COMPETITION_SERVER_HOST` | 比赛服务器地址 | - |
| `COMPETITION_AGENT_TOKEN` | 比赛认证令牌 | - |
| `COMPETITION_MCP_URL` | 比赛 MCP 直连 URL | - |
| `COMPETITION_LLM_BASE_URL` | 比赛内网 LLM 网关 | - |
| `ADVISOR_ENABLED` | 启用 Advisor | true |
| `ADVISOR_EVALUATE_INTERVAL` | 评估间隔（轮） | 3 |
| `ADVISOR_COMPRESS_INTERVAL` | 压缩间隔（轮） | 15 |

### settings.json

主要配置项：

```json
{
  "model": {
    "name": "qwen3.6-plus",
    "base_url": "https://coding.dashscope.aliyuncs.com/v1",
    "api_key": "${LLM_API_KEY}",
    "timeout": 120,
    "temperature": 0.1,
    "fallback_models": []
  },
  "timeouts": {
    "task": 3600,
    "tool_default": 300,
    "llm_call": 120,
    "mcp_connect": 30
  },
  "query": {
    "max_turns": 500,
    "context_window_tokens": 1048576,
    "context_reserve_tokens": 32768,
    "message_truncate_threshold": 16000,
    "parallel_tool_calls": true
  },
  "advisor": {
    "enabled": true,
    "evaluate_interval": 3,
    "compress_interval": 15
  },
  "mcp_servers": {
    "kali": {
      "command": "python3",
      "args": ["mcp_servers/kali_server.py"]
    },
    "null_zone_forum": {
      "command": "python3",
      "args": ["mcp_servers/null_zone_forum.py"],
      "env": {
        "NULL_ZONE_TOKEN": "${NULL_ZONE_TOKEN}",
        "NULL_ZONE_HOST": "${NULL_ZONE_HOST}"
      }
    }
  }
}
```

---

## 部署

### Docker

基于 `kalilinux/kali-rolling` 镜像，预装 Kali 工具集、fscan、nuclei。

```bash
docker compose build
docker compose up
```

docker-compose 配置：
- 网络模式：host（需要访问比赛靶机）
- 资源限制：4GB 内存 / 4 CPU
- Volume 挂载：`skills_v2`（只读）、`logs`、`ctf-workspace`
- 以 root 运行（渗透工具需要 root 权限）

### Kali 直接运行

```bash
./run_kali.sh competition   # 比赛自动模式
./run_kali.sh http://target # 单题攻击
./run_kali.sh repl          # 智能 REPL
```

脚本会自动创建虚拟环境、安装依赖。

### 远程文件同步

开发在 Windows，部署在远程 VPS 时，使用 `_sync_files.py` 同步：

```bash
python _sync_files.py
```

通过 Paramiko SSH 连接远程主机，SFTP 上传到宿主临时目录，再 `docker cp` 进容器。

---

## 目录结构

```
deploy/
├── app/
│   ├── cli.py                    # CLI 入口（4 种模式）
│   ├── repl.py                   # 智能 REPL
│   ├── interactive.py            # 旧版交互
│   ├── settings.py               # 配置系统（env > json > default）
│   ├── llm_client.py             # LLM 客户端（重试 + fallback）
│   ├── logger.py                 # 日志系统
│   ├── core/
│   │   ├── query.py              # Query 循环（核心引擎）
│   │   ├── loop_detector.py      # 循环检测器
│   │   └── time_manager.py       # 时间预算管理
│   ├── advisors/
│   │   └── ctf_advisor.py        # Advisor Agent（评估/压缩/侦察）
│   ├── prompts/
│   │   └── ctf_system_prompt.py  # 系统提示词构建器
│   ├── tools_v2/
│   │   ├── mcp/
│   │   │   └── client.py         # MCP 客户端（stdio + HTTP）
│   │   └── skill_engine.py       # 技能搜索引擎
│   └── memory/
│       └── token_stats.py        # Token 统计
├── mcp_servers/
│   ├── kali_server.py            # Kali MCP 服务器（17 工具）
│   └── null_zone_forum.py        # 论坛 MCP 服务器（22 工具）
├── skills_v2/                    # 150+ 攻击技能（SKILL.md）
├── settings.json                 # 配置文件
├── .env.example                  # 环境变量模板
├── Dockerfile                    # Kali Docker 镜像
├── docker-compose.yml            # Docker Compose
├── run.sh                        # Docker 启动脚本
└── run_kali.sh                   # Kali 直接启动脚本
```

---

## 常见问题

**LLM API Key 报错**

检查 `.env` 文件中 `LLM_API_KEY` 是否已填写，不能为空或占位符。

**MCP 服务器连接失败**

确认 `kali_server.py` 和 `null_zone_forum.py` 路径正确，Python 环境已安装 `mcp` 依赖。

**工具连续无输出或重复操作**

循环检测器会注入 `[LOOP_DETECTED]` 警告。如果 Agent 仍然重复，可以用 REPL 模式手动指导，或检查 Advisor 的 GUIDANCE 是否生效。

**上下文超长**

框架会自动分级截断（200K/500K/800K 阈值），关键系统消息（GUIDANCE、进度摘要）受保护不会被裁剪。

**模型频繁 fallback**

检查主模型 API 端点是否正确。可以在 `settings.json` 的 `fallback_models` 中添加备用模型。

**比赛模式不工作**

确认 `COMPETITION_SERVER_HOST` 和 `COMPETITION_AGENT_TOKEN` 已设置。比赛工具只在两个环境变量都存在时才会注册。

**Docker 构建慢**

Dockerfile 已配置清华源和阿里源加速。如果仍然慢，可以检查网络或使用 `./run_kali.sh` 直接在 Kali 运行。

---

## 许可证

MIT License
