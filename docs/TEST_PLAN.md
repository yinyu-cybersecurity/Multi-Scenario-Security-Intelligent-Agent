# CTF-Agent 测试计划

## 环境信息
- **部署环境**: Windows Docker Desktop
- **测试日期**: 2026-03-23

---

## Phase 1: 环境验证

### 1.1 容器状态
```bash
docker ps
docker logs ctf-agent --tail 50
```

### 1.2 进入容器
```bash
docker exec -it ctf-agent bash
```

### 1.3 Python 环境
```bash
python --version
pip list | grep -E "langgraph|langchain|chromadb"
```

### 1.4 工具检查
```bash
which nuclei sqlmap nmap
nuclei -version
sqlmap --version
nmap --version
```

---

## Phase 2: 模块测试

### 2.1 核心模块导入
```bash
python -c "
from config import config
from state import CTFState
from router import route_mode
from tool_framework import ToolRegistry
print('Core modules: OK')
print(f'Max rounds: {config.MAX_TOTAL_ROUNDS}')
"
```

### 2.2 工具注册
```bash
python -c "
from tools import load_all_tools
from tool_framework import ToolRegistry
load_all_tools(ToolRegistry)
tools = ToolRegistry.list_tools()
print(f'Registered tools: {len(tools)}')
for name in list(tools.keys())[:10]:
    print(f'  - {name}')
"
```

### 2.3 LLM 连接测试
```bash
python -c "
from llm_client import llm_client
from config import config
result = llm_client.chat('Hello, respond with OK')
print(f'LLM Response: {result[:100]}...')
"
```

---

## Phase 3: 功能测试

### 3.1 系统自检
```bash
python /app/ctf_agent_graph.py --skip
```

### 3.2 单工具测试 - Nmap
```bash
nmap -sn 127.0.0.1
```

### 3.3 单工具测试 - Nuclei
```bash
nuclei -u https://example.com -silent
```

### 3.4 单工具测试 - SQLMap
```bash
sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --batch --level=1
```

---

## Phase 4: 完整流程测试

### 4.1 运行任务
```bash
python /app/ctf_agent_graph.py --target http://testphp.vulnweb.com --skip
```

---

## 测试结果汇总

| Phase | 测试项 | 状态 |
|-------|--------|------|
| 1.1 | 容器启动 | ⬜ |
| 1.2 | Python环境 | ⬜ |
| 1.3 | 工具可用性 | ⬜ |
| 2.1 | 核心模块 | ⬜ |
| 2.2 | 工具注册 | ⬜ |
| 2.3 | LLM连接 | ⬜ |
| 3.1 | 系统自检 | ⬜ |
| 3.2 | Nmap测试 | ⬜ |
| 3.3 | Nuclei测试 | ⬜ |
| 4.1 | 完整流程 | ⬜ |

---

## 常见问题

### 容器不断重启
- 检查 config.yaml 是否存在
- 检查 LLM_API_KEY 是否配置

### 工具找不到
- 进入容器检查 `/app/thirdparty/` 目录
- 检查 `/root/go/bin/` 目录

### LLM 连接失败
- 检查网络连接
- 检查 API Key 是否有效