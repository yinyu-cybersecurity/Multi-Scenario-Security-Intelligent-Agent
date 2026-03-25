# CTF-Agent

基于 LangGraph 的智能 CTF 自动化解题系统 - 支持六大方向，AI驱动全流程

---

## 项目简介

CTF-Agent 是一个智能化的渗透测试代理，能够自主完成从信息侦察到漏洞利用的全流程。系统通过 LLM 驱动多兵种节点协同工作，支持 **Web 安全、内网渗透、密码学、逆向、Pwn、Misc** 六大方向。

### 核心特性

#### 🤖 AI驱动全流程
- **Web CTF**: 侦察 → 分析 → 攻击 → 验证 → 进化
- **内网渗透**: 后渗透 → 工具上传 → 隧道搭建 → 横向移动 → 权限提升
- **动态决策**: 所有决策节点由AI驱动，避免硬编码

#### 🛡️ 六大CTF方向
| 方向 | 节点 | AI决策函数 |
|------|------|-----------|
| Web | analyst, attacker, verifier | `get_analyst_prompt()`, `get_attacker_prompt()` |
| Internal Network | internal_recon, lateral_move, privilege_escalation | `_ai_decide_scan_strategy()`, `_ai_decide_lateral_strategy()` |
| Crypto | crypto_analyst, crypto_solver | `_ai_decide_decrypt_strategy()` |
| Pwn | pwn_analyst, pwn_exploiter | `_ai_decide_exploit_strategy()` |
| Reverse | reverse_analyst, reverse_decompiler | `_llm_reverse_analysis()` |
| Misc | misc_analyst, misc_extractor | `_llm_misc_analysis()` |

#### 🔧 40+ 安全工具
- **注入工具**: sqlmap, fenjing (SSTI)
- **漏洞扫描**: nuclei, xray, fscan, nmap, cve_scanner
- **反序列化**: ysoserial, phpggc, pickle-pwn, marshalsec
- **内网渗透**: impacket, crackmapexec, mimikatz, frp
- **域渗透**: bloodhound, petitpotam, rubeus
- **权限提升**: potato系列 (PrintSpoofer/SweetPotato)

#### ✨ 系统改进（2026-03 更新）
- **模块化状态类型**: 场景分离的状态定义（WebCTFState, InternalNetworkState, CryptoCTFState 等）
- **统一错误处理**: ToolResult 类型和 AI 驱动的错误恢复
- **并发控制**: LLMRateLimiter 实现的 API 调用限流
- **任务持久化**: SQLite 存储，支持断点续传
- **模块注册机制**: 延迟导入，代码简化 38%
- **拓扑决策对接**: 拓扑分析与攻击决策深度融合
- **统一日志系统**: 按任务/节点分离日志，控制台简洁输出
- **性能监控面板**: 节点/LLM/工具执行耗时统计
- **Web UI 优化**: 固定导航栏、节点拆卸、拓扑图可视化

---

## Quick Start

### 1. 环境要求
- Python 3.10+
- Docker (可选)

### 2. 配置
```bash
cp config.yaml.example config.yaml
```

编辑 `config.yaml`:
```yaml
# LLM 配置
LLM_API_KEY: "your-api-key"
LLM_BASE_URL: "https://api.deepseek.com/v1"
ANALYST_MODEL: "deepseek-chat"

# VPS配置 (内网渗透需要)
LOCAL_PUBLIC_IP: "your-vps-ip"
HTTP_SERVER_PORT: 8000
FRP_SERVER_PORT: 7000
FRP_SOCKS5_PORT: 10800
```

### 3. Web UI 部署 (推荐)

#### Docker 部署
```bash
docker-compose up -d

# 访问 Web UI
# Windows: http://localhost:5000
# Linux: http://服务器IP:5000
```

#### 本地运行
```bash
pip install -r requirements.txt

# Windows
start_web.bat

# Linux
chmod +x start_web.sh
./start_web.sh
```

### 4. 命令行模式
```bash
docker-compose --profile cli up -d ctf-agent-cli
docker exec -it ctf-agent-cli bash
python /app/app/ctf_agent_graph.py --target http://目标地址
```

### 5. 本地命令行运行
```bash
pip install -r requirements.txt
python app/ctf_agent_graph.py --target http://目标地址
```

---

## 目录结构

```
deploy/
├── app/                        # 核心代码
│   ├── ctf_agent_graph.py      # 主程序入口 & 图定义
│   ├── state.py                # CTFState 状态定义（原有）
│   ├── state_v2.py             # 增强状态定义（拓扑字段）
│   ├── state_types/            # [新增] 模块化状态类型
│   │   ├── base.py             # 基础状态（通用字段）
│   │   ├── web.py              # Web CTF 状态
│   │   ├── internal_network.py # 内网渗透状态
│   │   └── reducers.py         # 状态规约器
│   ├── module_registry.py      # [新增] 模块注册机制
│   ├── task_persistence.py     # [新增] 任务持久化
│   ├── attack_strategy_evaluator.py  # [新增] 策略评估
│   ├── context_compressor.py   # [新增] 上下文压缩
│   ├── logger.py               # [新增] 统一日志系统
│   ├── performance.py          # [新增] 性能监控
│   ├── router.py               # 节点路由逻辑
│   ├── llm_client.py           # LLM 客户端（并发控制）
│   ├── self_correction.py      # 自我纠错（AI驱动恢复）
│   ├── config.py               # 配置加载（常量集中）
│   ├── tool_framework.py       # 工具框架（NetworkScanTool 基类）
│   ├── tool_selector.py        # AI驱动工具选择
│   ├── analyst_prompt.py       # 分析兵提示词
│   ├── attacker_prompt.py      # 攻击兵提示词
│   ├── verifier_prompt.py      # 核验兵提示词
│   ├── innovator_agent.py      # 头脑风暴节点
│   ├── evolution.py            # 进化闭环
│   └── topology/               # 拓扑分析
├── tools/                      # 40+安全工具
├── internal_network/           # 内网渗透模块
│   ├── nodes.py                # 内网节点实现
│   └── post_exploit.py         # 后渗透处理
├── crypto/                     # 密码学模块
├── pwn/                        # Pwn模块
├── reverse/                    # 逆向模块
├── misc/                       # Misc模块
├── remote_executor/            # 远程执行模块
├── web/                        # [新增] Web UI & API
│   ├── api.py                  # REST API 服务
│   ├── templates/              # 前端模板
│   └── static/                 # 静态资源
├── docs/                       # [新增] 文档
│   ├── REFACTOR_PLAN.md        # 重构计划
│   └── IMPROVEMENT_LOG.md      # 改进日志
├── rag_builder/                # RAG知识检索
├── config.yaml.example         # 配置模板
├── refactoring_test.py         # [新增] 自动化测试脚本
├── self_check.py               # 自检脚本
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 工作流程

### Web CTF 流程
```
目标URL
    │
    ▼
[侦察兵] ──HTTP探测──→ [分析兵] ──漏洞识别──→ [攻击兵]
    │                      │                     │
    ▼                      ▼                     ▼
 page_features        vuln_candidates       attack_batch
                                                    │
                                                    ▼
                                              [核验兵]
                                                    │
                                    ┌───────────────┼───────────────┐
                                    ▼               ▼               ▼
                              [继续攻击]       [探索模式]      [创新模式]
```

### 内网渗透流程
```
获取Shell
    │
    ▼
[后渗透检测] ──发现内网──→ [工具上传] ──→ [隧道搭建]
    │                                          │
    ▼                                          ▼
internal_network_range                    SOCKS5代理
                                              │
                                              ▼
                                        [内网侦察]
                                              │
                                    ┌─────────┼─────────┐
                                    ▼         ▼         ▼
                              [凭据收集] [横向移动] [权限提升]
```

---

## 配置说明

### 完整配置示例
```yaml
# ===== LLM配置 =====
LLM_API_KEY: "sk-xxx"
LLM_BASE_URL: "https://api.deepseek.com/v1"

# ===== 模型选择 =====
ANALYST_MODEL: "deepseek-chat"      # 分析兵 - 需要强推理能力
ATTACKER_MODEL: "deepseek-chat"     # 攻击兵 - 需要代码生成能力
VERIFIER_MODEL: "deepseek-chat"     # 核验兵 - 需要长文本阅读
INNOVATOR_MODEL: "deepseek-chat"    # 头脑风暴 - 需要发散思维

# ===== 超时配置 =====
NODE_TIMEOUT: 1800              # 单个节点最大执行时间(秒) - 30分钟
TASK_TIMEOUT: 1200              # Web CTF任务超时(秒) - 20分钟
INTERNAL_TASK_TIMEOUT: 3000     # 内网渗透任务超时(秒) - 50分钟
TOOL_TIMEOUT_DEFAULT: 300       # 工具默认超时(秒) - 5分钟
TOOL_TIMEOUT_NETWORK: 600       # 网络扫描超时(秒) - 10分钟
LLM_TIMEOUT: 120                # LLM调用超时(秒) - 2分钟

# ===== 重试配置 =====
LLM_RETRY_COUNT: 3              # LLM调用重试次数
TOOL_RETRY_COUNT: 2             # 工具执行重试次数
LLM_MAX_CONCURRENT: 5           # LLM并发限制

# ===== 模式切换阈值 =====
FAILURE_SCORE_FOR_EXPLORE: 5.0  # 失败分达到此值进入探索模式
FAILURE_SCORE_FOR_INNOVATE: 10.0  # 失败分达到此值进入创新模式
FAILURE_SCORE_ABANDON: 15.0     # 失败分达到此值放弃任务
MAX_TOTAL_ROUNDS: 60            # 最大总运行轮次

# ===== VPS配置 (内网渗透必需) =====
LOCAL_PUBLIC_IP: "x.x.x.x"      # 本机公网IP
HTTP_SERVER_PORT: 8000          # HTTP文件服务器端口
FRP_SERVER_PORT: 7000           # frps监听端口
FRP_SOCKS5_PORT: 10800          # SOCKS5代理端口

# ===== 工具目录 =====
TOOLS_DIR: "/opt/tools"
FRP_DIR: "/opt/frp"
```

---

## AI决策节点

### 工具选择 (AI驱动)
```python
from tool_selector import ai_select_tools

tools = ai_select_tools(
    vuln_info={"type": "sql注入", "location": "param:id"},
    context={"tech_stack": ["php"], "db_type": "mysql"},
    attack_history=[{"tool": "sqlmap", "success": False}]
)
# 返回: ["sqlmap", "requests"]
```

### 内网渗透决策
```python
# AI决策扫描策略
scan_strategy = _ai_decide_scan_strategy(state, network_range)
# 返回: {"strategy": "quick", "ports": "1-1000"}

# AI决策横向移动
lateral_strategy = _ai_decide_lateral_strategy(target, target_host, credentials)
# 返回: {"method": "psexec", "credential_index": 0}
```

---

## 安全注意事项

1. **API Key 保护**: 不要将 `config.yaml` 上传到公开仓库
2. **攻击结果**: 攻击结果可能包含敏感信息，已添加到 `.gitignore`
3. **授权使用**: 仅在授权的 CTF 环境中使用

---

## 开发指南

### 添加新工具
```python
# tools/my_tool.py
from tool_framework import CommandLineTool

class MyTool(CommandLineTool):
    def name(self) -> str:
        return "my-tool"

    def description(self) -> str:
        return "My custom security tool"

    def get_command(self, target: str, params: dict) -> str:
        return f"my-tool -t {target}"

# 注册工具
ToolRegistry.register(MyTool())
```

### 添加新节点
```python
# 在 ctf_agent_graph.py 中
def my_custom_node(state: CTFState) -> Dict:
    # AI决策
    decision = _ai_my_decision(state)
    # 执行操作
    result = _execute_operation(decision)
    return {"custom_result": result}

# 添加到图
workflow.add_node("my_custom", my_custom_node)
```

---

## 许可证

MIT License

---

## 致谢

- LangGraph 框架
- DeepSeek / OpenAI API
- 各开源安全工具