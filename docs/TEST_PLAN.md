# CTF-Agent 测试计划

## 环境信息
- **部署环境**: Windows Docker Desktop
- **网络限制**: 无 IPv4 公网访问
- **测试日期**: 2026-03-23

---

## Phase 1: 环境验证测试

### 1.1 容器启动测试
```bash
# 查看容器状态
docker ps -a

# 查看容器日志
docker logs ctf-agent

# 进入容器
docker exec -it ctf-agent bash
```

**预期结果**:
- [ ] 容器状态为 `Up`
- [ ] 无错误日志

---

### 1.2 Python 环境测试
```bash
# 进入容器后执行
docker exec -it ctf-agent /opt/venv/bin/python --version

# 检查关键模块
docker exec -it ctf-agent /opt/venv/bin/python -c "
import langgraph
import langchain
import chromadb
print('Core modules OK')
"
```

**预期结果**:
- [ ] Python 3.11.x
- [ ] 核心模块导入成功

---

### 1.3 工具可用性测试
```bash
docker exec -it ctf-agent bash -c "
echo '=== Go Tools ==='
which nuclei && nuclei -version
which ffuf && ffuf -V
which httpx && httpx -version

echo '=== Python Tools ==='
which sqlmap && sqlmap --version
which nmap && nmap --version

echo '=== Check tools ==='
ls -la /app/thirdparty/
"
```

**预期结果**:
- [ ] nuclei 可用
- [ ] sqlmap 可用
- [ ] nmap 可用
- [ ] thirdparty 目录有工具

---

### 1.4 自检脚本测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python /app/self_check.py
```

**预期结果**:
- [ ] 全部检查通过

---

## Phase 2: 配置验证测试

### 2.1 配置文件测试
```bash
# 检查配置文件是否存在
docker exec -it ctf-agent ls -la /app/config.yaml

# 检查环境变量
docker exec -it ctf-agent env | grep -E "LLM|API|KEY"
```

**预期结果**:
- [ ] config.yaml 存在
- [ ] LLM_API_KEY 已设置

---

### 2.2 API 连接测试
```bash
# 测试 LLM API 连接
docker exec -it ctf-agent /opt/venv/bin/python -c "
import os
import requests

api_key = os.environ.get('LLM_API_KEY', '')
base_url = os.environ.get('LLM_BASE_URL', 'https://api.deepseek.com/v1')

print(f'Base URL: {base_url}')
print(f'API Key: {api_key[:10]}...')

# 测试连接
try:
    resp = requests.get(f'{base_url}/models', headers={'Authorization': f'Bearer {api_key}'}, timeout=10)
    print(f'Status: {resp.status_code}')
    print('API Connection: OK')
except Exception as e:
    print(f'Error: {e}')
"
```

**预期结果**:
- [ ] API 连接成功

---

## Phase 3: 单元功能测试

### 3.1 State 模块测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from app.state import CTFState

# 创建测试状态
state = CTFState(
    target_url='http://test.com',
    current_round=0,
    mode='web'
)
print(f'State created: {state.target_url}')
print('State module: OK')
"
```

---

### 3.2 LLM Client 测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from app.llm_client import LLMClient

client = LLMClient()
result = client.chat('Hello, respond with OK')
print(f'Response: {result[:100]}...')
"
```

---

### 3.3 Router 测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from app.router import route_after_recon

# 测试路由逻辑
print('Router module loaded')
print('Router: OK')
"
```

---

### 3.4 Tool Framework 测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from app.tool_framework import ToolRegistry

# 检查已注册工具
tools = ToolRegistry.list_tools()
print(f'Registered tools: {len(tools)}')
for name in list(tools.keys())[:10]:
    print(f'  - {name}')
"
```

---

## Phase 4: Web CTF 模块测试

### 4.1 本地靶场测试 (DVWA)

**前置条件**: 需要本地运行 DVWA

```bash
# 在另一个终端启动 DVWA
docker run -d -p 8080:80 --name dvwa vulnerables/dvwa
```

**测试命令**:
```bash
docker exec -it ctf-agent /opt/venv/bin/python /app/app/ctf_agent_graph.py \
    --target http://host.docker.internal:8080 \
    --mode web \
    --task "SQL注入测试"
```

**测试项目**:
- [ ] 能访问 DVWA
- [ ] 能识别 SQL 注入点
- [ ] 能执行 sqlmap

---

### 4.2 单工具测试

#### SQLMap 测试
```bash
docker exec -it ctf-agent sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --batch --level=1
```

#### Nuclei 测试
```bash
docker exec -it ctf-agent nuclei -u https://example.com -t cves/ -silent
```

#### Nmap 测试 (本地网络)
```bash
docker exec -it ctf-agent nmap -sn 127.0.0.1
```

---

## Phase 5: 内网渗透模块测试

由于 Windows Docker 无 IPv4，使用本地网络测试：

### 5.1 本地端口扫描
```bash
docker exec -it ctf-agent nmap -sV 127.0.0.1
```

### 5.2 内网模块加载测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from internal_network.nodes import InternalReconNode
from internal_network.credential_manager import CredentialManager

print('Internal network modules: OK')
"
```

---

## Phase 6: Crypto 模块测试

### 6.1 Crypto 模块加载
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from crypto.tools import CryptoTools

tools = CryptoTools()
print('Crypto modules: OK')
"
```

### 6.2 基础加密测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)
data = b'test123'
encrypted = cipher.encrypt(pad(data, 16))
decrypted = unpad(cipher.decrypt(encrypted), 16)
print(f'Original: {data}')
print(f'Decrypted: {decrypted}')
print('AES: OK')
"
```

---

## Phase 7: RAG & Memory 测试

### 7.1 RAG 模块测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from rag_builder.retriever import KnowledgeRetriever

print('RAG module: OK')
"
```

### 7.2 Memory 模块测试
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from memory.memory_manager import MemoryManager

mm = MemoryManager('/app/.memory')
print('Memory module: OK')
"
```

---

## Phase 8: 完整流程测试

### 8.1 单任务测试 (模拟)
```bash
docker exec -it ctf-agent /opt/venv/bin/python -c "
import sys
sys.path.insert(0, '/app')
from app.ctf_agent_graph import CTFAgentGraph

# 创建图实例
graph = CTFAgentGraph()
print('Graph created')

# 模拟状态
state = {
    'target_url': 'http://example.com',
    'mode': 'web',
    'current_round': 0
}
print('Initial state created')
print('Full flow test: Ready')
"
```

---

## 测试结果汇总

| Phase | 测试项 | 状态 | 备注 |
|-------|--------|------|------|
| 1.1 | 容器启动 | ⬜ | |
| 1.2 | Python环境 | ⬜ | |
| 1.3 | 工具可用性 | ⬜ | |
| 1.4 | 自检脚本 | ⬜ | |
| 2.1 | 配置文件 | ⬜ | |
| 2.2 | API连接 | ⬜ | |
| 3.1 | State模块 | ⬜ | |
| 3.2 | LLM Client | ⬜ | |
| 3.3 | Router | ⬜ | |
| 3.4 | Tool Framework | ⬜ | |
| 4.1 | 本地靶场 | ⬜ | |
| 4.2 | 单工具测试 | ⬜ | |
| 5.1 | 端口扫描 | ⬜ | |
| 5.2 | 内网模块 | ⬜ | |
| 6.1 | Crypto模块 | ⬜ | |
| 6.2 | 加密测试 | ⬜ | |
| 7.1 | RAG模块 | ⬜ | |
| 7.2 | Memory模块 | ⬜ | |
| 8.1 | 完整流程 | ⬜ | |

---

## 执行顺序

1. 先执行 Phase 1-2（环境验证）
2. 再执行 Phase 3（单元测试）
3. 然后 Phase 4-7（模块测试）
4. 最后 Phase 8（完整流程）

---

## 反馈格式

请将每个测试的输出贴给我，格式：

```
[Phase X.X] 测试名称
输出内容...
状态: ✅/❌
问题: (如有)
```