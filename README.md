# CTF-Agent 2.0

基于 LangGraph 的智能 CTF 自动化求解框架，支持 **Web、Pwn、Crypto、Reverse、Misc、内网渗透、云安全、AI安全** 八大CTF方向。

---

## 核心特性

### 多Agent协同架构
- **Explore Agent**: 信息收集与代码探索（只读权限）
- **Plan Agent**: 攻击策略规划（只读权限）
- **Attack Agent**: 漏洞利用执行（读写执行权限）
- **Verify Agent**: 结果验证与对抗测试（读写执行权限）

### 65+ 安全工具集成
| 分类 | 数量 | 核心工具 |
|------|------|----------|
| Web安全 | 34 | nmap, nuclei, sqlmap, xray, fscan, ffuf, dirsearch, hydra... |
| 密码学 | 5 | crypto_identifier, rsa_attacker, hash_analyzer, classical_cipher_solver |
| 二进制 | 3 | binary_analyzer, rop_builder, shellcode_generator |
| 逆向 | 4 | disassembler, decompiler, string_extractor, apk_analyzer |
| 杂项 | 5 | steganography_detector, forensics_analyzer, traffic_analyzer |
| AI安全 | 3 | ai_attacker, prompt_injector, model_extractor |
| OA攻击 | 4 | oa_exploiter (泛微/致远/通达/蓝凌) |
| 云安全 | 4 | cloud_scanner, container_escape, kube_attacker |
| 内网渗透 | 3 | privesc_scanner, potato_attack, ldap_domaindump |

### 自动交互支持
支持需要交互式输入的工具（如Gopherus），自动响应提示。

---

## 快速开始

### 本地运行 + Docker工具容器（推荐）

```bash
# 1. 安装Python依赖
pip install -r requirements.txt

# 2. 构建Docker工具镜像
chmod +x scripts/build-images.sh
./scripts/build-images.sh

# 3. 配置API密钥
cp config.yaml.example config.yaml
# 编辑config.yaml，填入LLM API密钥

# 4. 运行Agent
python -m app.main
```

### 工具镜像构建

```bash
# 构建所有镜像
docker build -t ctf-tools-web:latest -f docker/web-tools/Dockerfile .
docker build -t ctf-tools-pwn:latest -f docker/pwn-tools/Dockerfile .
docker build -t ctf-tools-ad:latest -f docker/ad-tools/Dockerfile .
docker build -t ctf-tools-deser:latest -f docker/deser-tools/Dockerfile .
docker build -t ctf-tools-misc:latest -f docker/misc-tools/Dockerfile .

# 或使用构建脚本
./scripts/build-images.sh
```

### Docker工具镜像列表

| 镜像名 | 工具 | 大小 | 用途 |
|--------|------|------|------|
| ctf-tools-web | nmap, nuclei, httpx, fscan, sqlmap... | ~800MB | Web安全扫描 |
| ctf-tools-pwn | pwntools, ROPgadget, pwndbg | ~300MB | 二进制利用 |
| ctf-tools-ad | crackmapexec, impacket, bloodhound | ~400MB | AD域渗透 |
| ctf-tools-deser | ysoserial, marshalsec, JNDIExploit | ~200MB | 反序列化攻击 |
| ctf-tools-misc | jwt_tool, ssrfmap, gopherus | ~150MB | 杂项工具 |

### 本地开发

```bash
# 克隆项目
git clone https://github.com/your-repo/ctf-agent.git
cd ctf-agent

# 安装依赖
pip install -r requirements.txt

# 配置API密钥
cp config.yaml.example config.yaml
# 编辑config.yaml，填入API密钥

# 运行
python -m app.ctf_agent_graph
```

---

## 架构

```
app/
├── agents/               # Agent实现
│   ├── base.py           # 基础Agent
│   └── autonomous_agent.py
├── tools_v2/             # 工具系统（65+工具）
│   └── tools/
│       ├── simple_tools.py        # Web安全工具Schema+Handler
│       ├── specialized_schemas.py  # 专业方向Schema
│       └── specialized_handlers.py # 专业方向Handler
├── memory/               # 记忆系统
│   ├── agent_memory.py   # Agent间通信
│   ├── prompt_cache.py   # Prompt缓存（90% Token节省）
│   ├── error_recovery.py # 错误恢复（指数退避）
│   └── incremental_memory.py # 增量记忆
├── capabilities/         # 能力模块
│   └── foundation.py     # 基础能力框架
├── coordinator/          # 协调器
│   └── dispatcher.py     # 任务分发
├── state_types/          # 状态类型定义
│   ├── web.py, crypto.py, pwn.py... # 各方向状态
│   └── reducers.py       # 状态归约器
├── skills/               # 技能配置
│   └── *.yaml            # YAML技能定义
├── ctf_agent_graph.py    # 主图定义
├── llm_client.py         # LLM客户端
├── flag_extractor_v2.py  # Flag提取器
└── router.py             # 路由器
```

---

## 工具详细列表

### Web安全工具 (34个)

#### P0级核心工具 (16个)
| 工具 | 功能 | Docker路径 |
|------|------|------------|
| nmap | 端口扫描 | /usr/bin/nmap |
| nuclei | 漏洞扫描 | /usr/local/bin/nuclei |
| httpx | HTTP探测 | /usr/local/bin/httpx |
| fscan | 内网综合扫描 | /usr/local/bin/fscan |
| sqlmap | SQL注入 | pipx (sqlmap) |
| ffuf | Web模糊测试 | /usr/local/bin/ffuf |
| dirsearch | 目录扫描 | /app/thirdparty/dirsearch |
| gobuster | 多协议爆破 | /usr/local/bin/gobuster |
| whatweb | 技术栈识别 | gem (whatweb) |
| crackmapexec | 内网渗透 | pipx (crackmapexec) |
| impacket | 协议工具包 | pipx (impacket) |
| bloodhound | AD分析 | pipx (bloodhound) |
| hydra | 密码爆破 | /usr/bin/hydra |
| xray | 被动扫描 | /usr/local/bin/xray |
| subfinder | 子域名发现 | /usr/local/bin/subfinder |
| frp | 内网穿透 | /opt/frp |

#### P1-P3级工具 (18个)
ysoserial, jwt_tool, ssrfmap, dalfox, httprobe, githacker, gopherus, phpggc, certipy, jndiexploit, jsfinder, xxeinjector, petitpotam, php_filter_chain, rubeus, mimikatz, pywhisker, marshalsec

### CTF专业方向工具

#### Crypto (密码学)
- `crypto_identifier`: 自动识别Base64/Hex/哈希/古典密码/RSA
- `rsa_attacker`: 小指数攻击、Fermat分解
- `hash_analyzer`: 哈希类型识别、彩虹表查询
- `classical_cipher_solver`: 凯撒、栅栏、维吉尼亚自动破解
- `encoding_decoder`: 多编码自动解码

#### Pwn (二进制漏洞)
- `binary_analyzer`: 保护检测、函数列表、字符串提取
- `rop_builder`: ROPgadget集成、自动gadget搜索
- `shellcode_generator`: msfvenom集成、多架构支持

#### Reverse (逆向工程)
- `disassembler`: 多架构反汇编
- `decompiler`: Ghidra/IDA/radare2
- `string_extractor`: 字符串提取
- `apk_analyzer`: APK反编译、权限分析

#### Misc (杂项)
- `steganography_detector`: LSB/DCT/FFT隐写检测
- `forensics_analyzer`: 内存/磁盘分析、文件恢复
- `traffic_analyzer`: PCAP解析、敏感信息提取
- `encoding_converter`: 多编码转换
- `qr_decoder`: 二维码解码

#### AI Security (AI安全)
- `ai_attacker`: Prompt注入、越狱攻击、模型窃取
- `prompt_injector`: Payload生成器
- `model_extractor`: 模型重建攻击

#### OA Exploit (OA系统攻击)
支持系统：泛微OA、致远OA、通达OA、蓝凌OA、信呼OA、用友NC/U8、金蝶EAS/K3

---

## 配置

### API密钥配置

```yaml
# config.yaml
llm:
  default_model: "glm-4-flash"
  api_keys:
    openai: "sk-xxx"
    anthropic: "sk-xxx"
    zhipu: "xxx"
```

### MCP插件配置

在 `.claude/settings.local.json` 中配置MCP服务器：
- `serena`: LSP代码分析
- `semgrep-plugin`: 静态代码扫描
- `context7`: 文档查询
- `playwright`: 浏览器自动化
- `chrome-devtools-mcp`: 浏览器调试

---

## 安全特性

### SSRF防护
所有HTTP工具调用 `validate_url_for_ssrf()`，阻止私有IP访问（内网扫描除外）。

### 命令注入防护
使用 `subprocess` 列表传参，禁止 `shell=True`，参数白名单验证。

### 权限分离
- Explore Agent: 仅 Read, Glob, Grep, LSP, WebFetch
- Plan Agent: Read, Glob, Grep, AskUserQuestion
- Attack Agent: Read, Write, Edit, Bash, MCP工具
- Verify Agent: Read, Bash, Semgrep扫描

### Docker安全
- 非root用户运行（ctfagent）
- sudo配置限制（仅允许安全工具）
- 敏感文件权限控制

---

## 开发

### 运行测试

```bash
pytest tests/ -v
```

### 代码审查

```bash
semgrep --config=auto app/
```

### 添加新工具

```python
# app/tools_v2/tools/specialized_schemas.py
TOOL_SCHEMAS["new_tool"] = {
    "name": "new_tool",
    "description": "工具描述",
    "inputSchema": {...}
}

# app/tools_v2/tools/specialized_handlers.py
async def new_tool_handler(...) -> Dict:
    # 实现逻辑
    return {"success": True, ...}

SPECIALIZED_HANDLERS["new_tool"] = new_tool_handler
```

---

## 文档

- [API文档](docs/API_DOCUMENTATION.md)
- [使用指南](docs/USAGE.md)
- [路线图](docs/ROADMAP.md)
- [贡献指南](CONTRIBUTING.md)
- [安全政策](SECURITY.md)

---

## 许可证

MIT License

---

## 贡献

欢迎提交 Issue 和 Pull Request！

---

## 更新日志

见 [CHANGELOG.md](CHANGELOG.md)