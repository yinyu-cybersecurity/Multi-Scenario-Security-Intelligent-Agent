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

### 1. 配置
```bash
cp config.yaml.example config.yaml
# 编辑 config.yaml 填入 API Key
```

### 2. 构建并启动
```bash
docker-compose build
docker-compose up -d
```

### 3. 运行测试
```bash
# 进入容器
docker exec -it ctf-agent bash

# 系统自检
python /app/ctf_agent_graph.py --skip

# 运行任务
python /app/ctf_agent_graph.py --target http://目标地址
```

---

## 目录结构

```
├── app/                    # 核心代码
│   ├── ctf_agent_graph.py  # 主程序入口
│   ├── state.py            # 状态定义
│   ├── router.py           # 路由逻辑
│   ├── llm_client.py       # LLM客户端
│   ├── config.py           # 配置加载
│   └── topology/           # 拓扑分析
├── tools/                  # 33个安全工具
├── internal_network/       # 内网渗透模块
├── crypto/                 # 密码学模块
├── pwn/                    # Pwn模块
├── reverse/                # 逆向模块
├── misc/                   # Misc模块
├── memory/                 # 记忆系统
├── rag_builder/            # RAG知识检索
├── docs/                   # 文档
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Docker 使用说明

### 构建镜像
```bash
docker-compose build
```

### 启动容器
```bash
docker-compose up -d
```

### 进入容器
```bash
docker exec -it ctf-agent bash
```

### 查看日志
```bash
docker logs -f ctf-agent
```

### 停止容器
```bash
docker-compose down
```

---

## 配置说明

编辑 `config.yaml`：

```yaml
# LLM 配置
LLM_API_KEY: "your-api-key"
LLM_BASE_URL: "https://api.deepseek.com/v1"

# 模型配置
ANALYST_MODEL: "deepseek-chat"
ATTACKER_MODEL: "deepseek-chat"

# 系统控制
MAX_TOTAL_ROUNDS: 60
HITL_FAILURE_SCORE: 15.0
```

---

## 文档

- [项目路线图](docs/ROADMAP.md)
- [贡献指南](docs/CONTRIBUTING.md)
- [测试计划](docs/TEST_PLAN.md)

---

## License

MIT License