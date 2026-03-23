# ctf_agent

腾讯云黑客松智能渗透挑战赛 - 基于 LangGraph 的 CTF 自动化解题系统

---

## 项目简介

CTF-Agent 是一个智能化的渗透测试代理，能够自主完成从信息侦察到漏洞利用的全流程。系统通过 LLM 驱动多兵种节点协同工作，支持 Web 安全、内网渗透、密码学、逆向、Pwn、Misc 六大方向。

### 核心能力

- **自动场景识别**: 6种CTF方向自动切换
- **33个安全工具**: SQL注入、SSTI、XXE、CVE利用、内网渗透全覆盖
- **四大赛区支持**: SRC场景、CVE/Cloud/AI、多层网络/OA、AD域渗透
- **三层记忆系统**: 工作记忆 + 文件记忆 + RAG知识检索
- **自纠错机制**: 自动检测并恢复执行错误

### 技术栈

- **框架**: LangGraph StateGraph
- **LLM**: DeepSeek / OpenAI 兼容 API
- **向量库**: ChromaDB + Sentence Transformers
- **容器**: Docker + Docker Compose

---

## Quick Start

### 1. Configure
```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your API key and settings
```

### 2. Build and Run with Docker
```bash
docker-compose build
docker-compose up -d
```

### 3. Run Self-Check
```bash
docker exec ctf-agent python /app/self_check.py
```

---

## Directory Structure

```
├── app/                    # Core application code
│   ├── ctf_agent_graph.py  # Main graph orchestration
│   ├── state.py            # CTFState definition
│   ├── router.py           # Node routing logic
│   └── ...
├── tools/                  # 33 security tools
├── internal_network/       # AD/Lateral movement
├── crypto/                 # Cryptography module
├── memory/                 # Three-layer memory
├── rag_builder/            # Knowledge retrieval
├── docs/                   # Documentation
├── .github/                # GitHub workflows & templates
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Supported Sectors

| Sector | 攻击类型 | 工具 |
|--------|----------|------|
| Web Security | SQL注入、SSTI、XSS、XXE | sqlmap, fenjing, xsser |
| CVE/Cloud/AI | Log4Shell, Spring4Shell, Shiro | nuclei, jndi-exploit |
| Multi-layer Network | 横向移动、OA漏洞 | impacket, crackmapexec |
| AD Domain | AS-REP Roasting, Kerberoasting | KerberosAttacker |

---

## Documentation

- [项目路线图](docs/ROADMAP.md)
- [贡献指南](docs/CONTRIBUTING.md)

---

## License

MIT License