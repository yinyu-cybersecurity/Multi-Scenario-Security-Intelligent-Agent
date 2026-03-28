# CTF-Agent

基于 LangGraph 的智能 CTF 自动化解题系统 - AI驱动全流程，支持六大CTF方向

---

## 项目简介

CTF-Agent 是一个智能化的渗透测试代理，能够自主完成从信息侦察到漏洞利用的全流程。系统通过 LLM 驱动多兵种节点协同工作，支持 **Web安全、内网渗透、密码学、逆向、Pwn、Misc、AI安全、云安全** 八大方向。

### 核心特性

#### 🤖 AI驱动全流程
- **Web CTF**: 侦察 → 分析 → 攻击 → 验证 → 进化
- **内网渗透**: 后渗透 → 工具上传 → 隧道搭建 → 横向移动 → 权限提升 → 持久化
- **动态决策**: 所有决策节点由AI驱动，避免硬编码

#### 🛡️ 八大CTF方向
| 方向 | 核心文件 | 关键节点 |
|------|---------|---------|
| Web | app/ctf_agent_graph.py | recon, analyst, attacker, verifier, innovator |
| Internal Network | internal_network/nodes.py | post_exploit, internal_recon, lateral_move, privilege_escalation |
| Crypto | crypto/nodes.py | crypto_analyst, crypto_solver |
| Pwn | pwn/nodes.py | pwn_analyst, pwn_exploiter |
| Reverse | reverse/nodes.py | reverse_analyst, reverse_decompiler |
| Misc | misc/nodes.py | misc_analyst, misc_extractor |
| AI Security | ai_security/nodes.py | ai_analyst, model_attacker |
| Cloud Security | cloud_security/nodes.py | cloud_recon, cloud_exploit |

#### 🔧 49 模块化安全工具
| 分类 | 工具列表 |
|------|---------|
| **漏洞扫描** | nuclei_tool, xray_tool, fscan_tool, nmap_tool, cve_scanner |
| **注入攻击** | sqlmap_tool, fenjing_tool (SSTI), dalfox_tool (XSS), xxe_injector_tool |
| **反序列化** | ysoserial_tool, phpggc_tool, marshalsec_tool, pickle_pwn_tool, phar_gen_tool |
| **内网渗透** | impacket_tools, crackmapexec_tool, mimikatz_tool, msf_tool |
| **域渗透** | bloodhound_tool, petitpotam_tool, rubeus_tool, kerberos_attacks |
| **权限提升** | potato_tool, privesc_tool |
| **SSRF利用** | ssrfmap_tool, gopherus_tool, ssrf_scanner |
| **目录扫描** | dirsearch_tool, ffuf_tool |
| **信息收集** | jsfinder_tool, jwt_tool, httpx_tool, subfinder_tool, git_hacker_tool |
| **OA漏洞** | oa_exploiter, ajpshooter_tool |
| **隧道/代理** | frp_manager |
| **云安全** | cloud_scanner |
| **容器安全** | container_escape_tool |
| **AI攻击** | ai_attacker |
| **其他** | hydra_tool, flask_unsign_tool, jndi_exploit_tool, payload_mutator, db_attacks |

#### ✨ 系统特性（2026-03 更新）
- **模块化状态类型**: 8种场景状态（WebCTFState, InternalNetworkState, CryptoCTFState等）
- **统一日志系统**: 按任务/节点分离日志，控制台简洁输出
- **性能监控面板**: 节点/LLM/工具执行耗时统计，持久化存储
- **拓扑分析**: 站点结构可视化、页面差异检测、剪枝优化
- **任务持久化**: SQLite存储，支持断点续传
- **并发控制**: LLMRateLimiter API调用限流
- **AI驱动改进**: Flag验证、漏洞链分析、智能工具选择、规则过滤
- **会话管理**: SSH/Shell会话创建后自动验证有效性
- **线程安全**: 多任务并发时日志隔离
- **远程执行**: 文件传输、隧道管理、HTTP服务器

---

## Quick Start

### 1. 环境要求
- Python 3.10+
- Docker (可选，推荐)

### 2. 配置
```bash
cp config.yaml.example config.yaml
```

编辑 `config.yaml`，填入API Key：
```yaml
LLM_API_KEY: "your-api-key"
LLM_BASE_URL: "https://api.deepseek.com/v1"
```

### 3. 启动 Web UI

#### Docker 部署 (推荐)
```bash
docker-compose up -d --build
docker logs -f ctf-agent
# 访问: http://localhost:54565/fisher_ctf_agent/monitor
```

#### 本地运行
```bash
pip install -r requirements.txt
# Windows
start_web.bat
# Linux/Mac
./start_web.sh
# 访问: http://localhost:54565/fisher_ctf_agent/monitor
```

#### Web UI 功能
- **任务管理**: 创建/暂停/恢复任务
- **实时监控**: 节点执行状态、日志流
- **拓扑图**: 站点结构可视化
- **性能面板**: 耗时统计
- **模块管理**: 启用/禁用功能模块

### 4. 命令行模式
```bash
python app/ctf_agent_graph.py --target http://目标地址
--mode exploit      # 直接攻击模式
--mode explore      # 探索模式
--max-rounds 30     # 最大轮次
```

---

## 目录结构

```
deploy/
├── app/                        # 核心代码
│   ├── ctf_agent_graph.py      # 主程序入口 (147KB)
│   ├── state_v2.py             # 状态定义
│   ├── state_types/            # 模块化状态类型
│   │   ├── base.py             # 基础状态
│   │   ├── web.py              # Web CTF状态
│   │   ├── internal_network.py # 内网渗透状态
│   │   ├── crypto.py           # 密码学状态
│   │   ├── pwn.py              # Pwn状态
│   │   ├── reverse.py          # 逆向状态
│   │   ├── misc.py             # Misc状态
│   │   ├── ai_security.py      # AI安全状态
│   │   ├── cloud.py            # 云安全状态
│   │   └── reducers.py         # 状态规约器
│   ├── nodes/                  # 节点辅助模块
│   ├── topology/               # 拓扑分析
│   │   ├── analyzer.py         # 站点分析
│   │   ├── builder.py          # 拓扑构建
│   │   ├── pruner.py           # 剪枝优化
│   │   ├── page_diff.py        # 页面差异检测
│   │   └── visualizer.py       # 可视化
│   ├── logger.py               # 统一日志系统
│   ├── performance.py          # 性能监控
│   ├── llm_client.py           # LLM客户端
│   ├── router.py               # 节点路由
│   ├── tool_framework.py       # 工具框架基类
│   ├── tool_selector.py        # AI工具选择
│   ├── self_correction.py      # 自我纠错
│   ├── context_compressor.py   # 上下文压缩
│   ├── task_persistence.py     # 任务持久化
│   ├── evolution.py            # 进化闭环
│   ├── flag_validator.py       # Flag验证
│   ├── innovator_agent.py      # 创新节点
│   └── prompts/                # 提示词模块
├── tools/                      # 49个安全工具
│   ├── __init__.py             # 自动注册机制
│   ├── nmap_tool.py            # 端口扫描
│   ├── sqlmap_tool.py          # SQL注入
│   ├── fscan_tool.py           # 内网扫描
│   ├── nuclei_tool.py          # 漏洞扫描
│   ├── impacket_tools.py       # 内网工具集
│   └── ...                     # 其他工具
├── internal_network/           # 内网渗透模块
│   ├── nodes.py                # 内网节点 (73KB)
│   ├── post_exploit.py         # 后渗透处理
│   ├── advanced_operations.py  # 高级操作
│   ├── credential_manager.py   # 凭据管理
│   ├── kerberos_attacks.py     # Kerberos攻击
│   └── prompts.py              # 提示词
├── crypto/                     # 密码学模块
│   ├── nodes.py                # 密码学节点
│   ├── tools.py                # 密码学工具
│   └── prompts.py              # 提示词
├── pwn/                        # Pwn模块
│   ├── nodes.py                # Pwn节点
│   ├── tools.py                # Pwn工具
│   └── prompts.py              # 提示词
├── reverse/                    # 逆向模块
│   ├── nodes.py                # 逆向节点
│   ├── tools.py                # 逆向工具
│   └── prompts.py              # 提示词
├── misc/                       # Misc模块
│   ├── nodes.py                # Misc节点
│   ├── tools.py                # Misc工具
│   └── prompts.py              # 提示词
├── ai_security/                # AI安全模块
│   ├── nodes.py                # AI安全节点
├── cloud_security/             # 云安全模块
│   ├── nodes.py                # 云安全节点
├── remote_executor/            # 远程执行模块
│   ├── executors.py            # 远程执行器
│   ├── session_manager.py      # 会话管理
│   ├── tunnel_manager.py       # 隧道管理
│   ├── file_transfer.py        # 文件传输
│   └── http_server.py          # HTTP服务器
├── memory/                     # 记忆管理模块
│   ├── memory_manager.py       # 记忆管理
│   ├── performance_persistence.py # 性能持久化
│   └── token_stats.py          # Token统计
├── rag_builder/                # RAG知识检索
│   ├── vector_store.py         # 向量存储
│   └ retriever.py              # 检索器
├── web/                        # Web UI
│   ├── api.py                  # REST API (75KB)
│   ├── templates/              # HTML模板
│   │   ├── monitor.html        # 监控页面
│   │   ├── topology.html       # 拓扑页面
│   │   └── modules.html        # 模块管理
│   └── static/                 # 静态资源
├── thirdparty/                 # 第三方工具 (22个)
│   ├── nuclei/                 # 漏洞扫描
│   ├── xray/                   # 漏洞扫描
│   ├── SSRFmap/                # SSRF利用
│   ├── Gopherus/               # Gopher生成
│   ├── Githacker/              # .git泄露
│   ├── phpggc/                 # PHP反序列化
│   ├── marshalsec/             # Java反序列化
│   ├── ysoserial/              # Java反序列化
│   ├── jwt_tool/               # JWT利用
│   ├── JSFinder/               # JS发现
│   ├── XXEinjector/            # XXE注入
│   ├── PetitPotam/             # AD认证攻击
│   ├── Ghostcat/               # AJP利用
│   ├── jndiexploit/            # JNDI利用
│   ├── rubeus/                 # Kerberos
│   ├── ffuf/                   # 目录爆破
│   ├── httpx/                  # HTTP探测
│   ├── subfinder/              # 子域名发现
│   ├── frp/                    # 内网穿透
│   ├── fscan_linux/            # 内网扫描
│   ├── fscan_windows/          # 内网扫描
│   └── php_filter_chain_generator/
├── docs/                       # 文档 (24个)
├── tests/                      # 单元测试
├── test_suite/                 # 测试套件
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── config.yaml.example
```

---

## 工作流程

### Web CTF 流程
```
目标URL → [侦察兵] → [分析兵] → [攻击兵] → [核验兵]
              │           │           │
              ▼           ▼           ▼
         page_features  vuln_candidates  attack_batch
                                           │
                                           ▼
                                     [进化/创新/探索]
```

### 内网渗透流程
```
获取Shell → [后渗透] → [工具上传] → [隧道搭建] → [内网侦察]
                                               │
                        ┌──────────────────────┼──────────────────────┐
                        ▼                      ▼                      ▼
                  [凭据收集]              [横向移动]              [权限提升]
                        │                      │                      │
                        ▼                      ▼                      ▼
                  [持久化] ──────────────→ [Flag搜索]
```

---

## 配置说明

```yaml
# LLM配置
LLM_API_KEY: "sk-xxx"
LLM_BASE_URL: "https://api.deepseek.com/v1"
ANALYST_MODEL: "deepseek-chat"
ATTACKER_MODEL: "deepseek-chat"

# 超时配置
NODE_TIMEOUT: 1800          # 节点超时 30分钟
TASK_TIMEOUT: 1200          # Web CTF 20分钟
INTERNAL_TASK_TIMEOUT: 3000 # 内网渗透 50分钟

# VPS配置 (内网渗透必需)
LOCAL_PUBLIC_IP: "x.x.x.x"
HTTP_SERVER_PORT: 8000
FRP_SERVER_PORT: 7000
FRP_SOCKS5_PORT: 10800

# 模式切换阈值
FAILURE_SCORE_FOR_EXPLORE: 5.0
FAILURE_SCORE_FOR_INNOVATE: 10.0
MAX_TOTAL_ROUNDS: 60
```

---

## 开发指南

### 添加新工具
```python
# tools/my_tool.py
from tool_framework import CommandLineTool

class MyTool(CommandLineTool):
    def name(self) -> str:
        return "my-tool"
    def get_command(self, target: str, params: dict) -> str:
        return f"my-tool -t {target}"

# 自动注册 (tools/__init__.py 会扫描加载)
```

### 添加新节点
```python
# 在对应模块的 nodes.py 中
def my_node(state: CTFState) -> Dict:
    decision = ai_decide(state)
    result = execute(decision)
    return {"result": result}
```

---

## 统计信息

| 项目 | 数量 |
|------|------|
| 安全工具 (tools/) | 49 |
| 第三方工具 (thirdparty/) | 22 |
| CTF方向模块 | 8 |
| 状态类型 | 8 |
| 文档文件 | 24 |
| 核心代码行数 | ~50,000 |

---

## 安全注意

1. **API Key保护**: 不要上传 `config.yaml`
2. **授权使用**: 仅在授权CTF环境使用
3. **攻击结果敏感**: 已添加到 `.gitignore`

---

## 许可证

MIT License

---

## 致谢

- LangGraph 框架
- DeepSeek / OpenAI API
- 各开源安全工具