# Docker工具容器分离架构设计

**版本**: 1.0
**日期**: 2026-04-02
**状态**: 待审核

---

## 一、设计目标

将CTF-Agent从整体Docker部署升级为**核心宿主机 + 工具容器化**的分离架构：

1. **Agent核心在宿主机运行** - 状态管理、LLM调用、HTTP工具
2. **安全工具在Docker容器隔离执行** - 扫描工具、攻击工具、渗透工具
3. **按需混合容器策略** - 高频工具持久容器池，低频工具临时容器
4. **Host网络模式** - 容器直接访问目标网络，无网络隔离开销

---

## 二、架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                     宿主机 (Agent核心运行)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Agent核心                                                │  │
│  │  - AutonomousAgent                                        │  │
│  │  - Memory System                                          │  │
│  │  - Coordinator                                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  DockerToolExecutor                                       │  │
│  │  - 高频工具: 持久容器池 (nmap, nuclei, httpx, fscan)       │  │
│  │  - 低频工具: 临时容器 (ysoserial, jwt_tool, ...)          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Docker Daemon                                            │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐            │  │
│  │  │web-tools   │ │pwn-tools   │ │misc-tools  │            │  │
│  │  │(持久容器)  │ │(持久容器)  │ │(临时容器)  │            │  │
│  │  └────────────┘ └────────────┘ └────────────┘            │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                           │
                           │ Host网络模式
                           ▼
                    [ 目标网络 ]
```

### 2.2 核心组件

| 组件 | 文件位置 | 职责 |
|------|----------|------|
| DockerToolExecutor | `app/tools_v2/docker_executor.py` | Docker容器执行入口 |
| ContainerPool | `app/tools_v2/container_pool.py` | 容器池管理 |
| tool_images | `app/tools_v2/tool_images.py` | 工具镜像配置 |
| run_command | `app/tools_v2/tools/simple_tools.py` | 修改为路由到Docker |

---

## 三、工具镜像设计

### 3.1 镜像划分

| 镜像名 | 工具列表 | 大小估算 | 容器策略 |
|--------|----------|----------|----------|
| `ctf-tools-web` | nmap, nuclei, httpx, fscan, sqlmap, ffuf, dirsearch, xray, subfinder, gobuster, whatweb, hydra, dalfox, httprobe | ~800MB | 持久容器池 (3个) |
| `ctf-tools-pwn` | pwntools, ROPgadget, binary_analyzer, shellcode_generator | ~300MB | 持久容器池 (2个) |
| `ctf-tools-ad` | crackmapexec, impacket, bloodhound, certipy, ldapdomaindump, pywhisker, rubeus, mimikatz | ~400MB | 临时容器 |
| `ctf-tools-deser` | ysoserial, marshalsec, JNDIExploit, phpggc | ~200MB | 临时容器 |
| `ctf-tools-misc` | stegsolve, binwalk, foremost, exiftool, jwt_tool, ssrfmap, gopherus, githacker | ~150MB | 临时容器 |

### 3.2 工具分类依据

**高频工具（持久容器）**：
- nmap, nuclei, httpx, fscan - 网络扫描高频使用
- sqlmap, ffuf, dirsearch - Web渗透常用
- xray, subfinder - 辅助扫描

**低频工具（临时容器）**：
- 反序列化工具 - 特定场景使用
- AD域工具 - 内网渗透专用
- 杂项工具 - 按需启动

### 3.3 镜像Dockerfile位置

```
docker/
├── web-tools/
│   └── Dockerfile          # Web安全工具镜像
├── pwn-tools/
│   └── Dockerfile          # Pwn工具镜像
├── ad-tools/
│   └── Dockerfile          # AD域工具镜像
├── deser-tools/
│   └── Dockerfile          # 反序列化工具镜像
└── misc-tools/
    └── Dockerfile          # 杂项工具镜像
```

---

## 四、核心代码设计

### 4.1 文件结构

```
app/tools_v2/
├── docker_executor.py      # Docker执行器（新增）
├── container_pool.py       # 容器池管理（新增）
├── tool_images.py          # 工具镜像配置（新增）
└── tools/
    └── simple_tools.py     # 修改run_command()路由
```

### 4.2 DockerToolExecutor

```python
class DockerToolExecutor:
    """Docker工具执行器"""
    
    def __init__(self, pool: ContainerPool):
        self.pool = pool
        self.client = docker.from_env()
    
    async def execute(
        self,
        tool_name: str,
        command: list,
        timeout: int = 300,
        volume_mounts: dict = None
    ) -> Dict:
        """执行工具命令
        
        Args:
            tool_name: 工具名称
            command: 命令列表
            timeout: 超时时间（秒）
            volume_mounts: 卷挂载 {容器路径: 宿主机路径}
            
        Returns:
            {"success": bool, "stdout": str, "stderr": str}
        """
        
    def _get_container(self, tool_name: str) -> Container:
        """获取或创建容器"""
```

### 4.3 ContainerPool

```python
class ContainerPool:
    """容器池管理"""
    
    def __init__(self, config: dict):
        self.pools = {}  # {pool_name: [container1, container2, ...]}
        self.available = {}  # {pool_name: asyncio.Queue}
        self.config = config
        
    async def acquire(self, pool_name: str, timeout: int = 10) -> Container:
        """获取可用容器
        
        Args:
            pool_name: 池名称 (web/pwn)
            timeout: 等待超时
            
        Returns:
            可用容器对象
            
        Raises:
            TimeoutError: 池耗尽且超时
        """
        
    def release(self, pool_name: str, container: Container):
        """释放容器回池"""
        
    async def initialize(self):
        """初始化持久容器池"""
        
    async def cleanup(self):
        """清理容器池"""
```

### 4.4 工具镜像映射

```python
# tool_images.py
TOOL_IMAGE_MAPPING = {
    # Web工具 - 高频
    "nmap": {"image": "ctf-tools-web", "persistent": True},
    "nuclei": {"image": "ctf-tools-web", "persistent": True},
    "httpx": {"image": "ctf-tools-web", "persistent": True},
    "fscan": {"image": "ctf-tools-web", "persistent": True},
    "sqlmap": {"image": "ctf-tools-web", "persistent": True},
    "ffuf": {"image": "ctf-tools-web", "persistent": True},
    "dirsearch": {"image": "ctf-tools-web", "persistent": True},
    "xray": {"image": "ctf-tools-web", "persistent": True},
    "subfinder": {"image": "ctf-tools-web", "persistent": True},
    
    # Pwn工具 - 高频
    "binary_analyzer": {"image": "ctf-tools-pwn", "persistent": True},
    "rop_builder": {"image": "ctf-tools-pwn", "persistent": True},
    
    # AD工具 - 低频
    "crackmapexec": {"image": "ctf-tools-ad", "persistent": False},
    "impacket": {"image": "ctf-tools-ad", "persistent": False},
    "bloodhound": {"image": "ctf-tools-ad", "persistent": False},
    "certipy": {"image": "ctf-tools-ad", "persistent": False},
    "mimikatz": {"image": "ctf-tools-ad", "persistent": False},
    
    # 反序列化 - 低频
    "ysoserial": {"image": "ctf-tools-deser", "persistent": False},
    "marshalsec": {"image": "ctf-tools-deser", "persistent": False},
    "jndiexploit": {"image": "ctf-tools-deser", "persistent": False},
    
    # 杂项 - 低频
    "jwt_tool": {"image": "ctf-tools-misc", "persistent": False},
    "ssrfmap": {"image": "ctf-tools-misc", "persistent": False},
    "gopherus": {"image": "ctf-tools-misc", "persistent": False},
    "githacker": {"image": "ctf-tools-misc", "persistent": False},
}

CONTAINER_POOL_CONFIG = {
    "web": {"count": 3, "image": "ctf-tools-web:latest"},
    "pwn": {"count": 2, "image": "ctf-tools-pwn:latest"},
}
```

---

## 五、执行流程

### 5.1 工具调用流程

```
1. Handler调用 run_command(["nmap", "-sV", "target"])
                    ↓
2. 查询 TOOL_IMAGE_MAPPING["nmap"] → {"image": "web", "persistent": True}
                    ↓
3. DockerToolExecutor.execute()
   ├── persistent=True: pool.acquire("web") → container
   └── persistent=False: 创建临时容器
                    ↓
4. container.exec_run(cmd) → (exit_code, output)
                    ↓
5. persistent=True: pool.release(container)
   persistent=False: container.remove()
                    ↓
6. 返回 {"success": bool, "stdout": str, "stderr": str}
```

### 5.2 run_command() 修改

```python
async def run_command(
    cmd: list,
    timeout: int = 300,
    interactive: bool = False,
    inputs: list = None
) -> Dict[str, Any]:
    """执行命令并返回结果"""
    
    tool_name = cmd[0] if cmd else None
    
    # 检查是否应该用Docker执行
    if config.docker.enabled and tool_name in TOOL_IMAGE_MAPPING:
        return await docker_executor.execute(
            tool_name=tool_name,
            command=cmd,
            timeout=timeout
        )
    
    # 降级到本地执行
    if config.docker.fallback_to_local:
        return await _run_local_command(cmd, timeout, interactive, inputs)
    
    return {"success": False, "error": f"工具 {tool_name} 未配置Docker镜像"}
```

---

## 六、错误处理

### 6.1 错误类型与处理

| 错误类型 | 处理方式 |
|----------|----------|
| Docker未启动 | 降级到本地执行（如果工具已安装） |
| 镜像不存在 | 返回错误 + 提示构建命令 |
| 容器启动超时 | 重试1次，失败则返回错误 |
| 容器池耗尽 | 等待5秒，超时则创建临时容器 |
| 执行超时 | `docker stop` 强制终止 |
| 资源不足 | 清理闲置容器后重试 |

### 6.2 错误处理代码

```python
async def execute(self, tool_name: str, command: list, timeout: int = 300) -> Dict:
    try:
        # 尝试Docker执行
        container = await self._get_container(tool_name)
        exit_code, output = container.exec_run(command)
        self._release_container(tool_name, container)
        return {"success": exit_code == 0, "stdout": output.decode()}
        
    except docker.errors.DockerException as e:
        # Docker不可用，降级本地
        if self.config.fallback_to_local:
            return await self._run_local(command, timeout)
        return {"success": False, "error": f"Docker错误: {e}"}
        
    except asyncio.TimeoutError:
        # 执行超时
        container.stop()
        return {"success": False, "error": "执行超时"}
```

---

## 七、配置设计

### 7.1 配置文件

```yaml
# config.yaml 新增
docker:
  enabled: true
  container_pools:
    web: 3
    pwn: 2
  fallback_to_local: true  # Docker不可用时降级本地执行
  timeout:
    container_start: 30
    execution: 300
  volumes:
    # 共享目录
    /tmp/ctf_shared: /shared
```

### 7.2 环境变量

```bash
# 可选环境变量
DOCKER_HOST=unix:///var/run/docker.sock
DOCKER_TIMEOUT=60
```

---

## 八、依赖变更

### 8.1 requirements.txt 新增

```
# Docker SDK
docker>=7.0.0
```

### 8.2 系统依赖

- Docker Engine 24.0+
- Docker Python SDK

---

## 九、迁移策略

### 9.1 向后兼容

1. **配置项可选** - `docker.enabled` 默认为 `true`，设为 `false` 回退本地执行
2. **渐进迁移** - 先迁移高频工具，逐步扩展
3. **降级机制** - Docker不可用时自动降级本地执行

### 9.2 迁移步骤

1. Phase 1: 实现核心框架（docker_executor, container_pool）
2. Phase 2: 构建web-tools镜像，迁移nmap, nuclei, httpx
3. Phase 3: 构建其他镜像，迁移剩余工具
4. Phase 4: 移除旧的本地工具依赖

---

## 十、验收标准

### 10.1 功能验收

- [ ] 容器池正确初始化
- [ ] 高频工具使用持久容器
- [ ] 低频工具使用临时容器
- [ ] 执行结果正确返回
- [ ] Docker不可用时正确降级

### 10.2 性能验收

- [ ] 高频工具启动时间 < 100ms（容器池预热）
- [ ] 低频工具启动时间 < 5s（临时容器创建）
- [ ] 内存占用合理（容器池 < 2GB）

### 10.3 安全验收

- [ ] 容器无特权模式
- [ ] 容器无敏感目录挂载
- [ ] 执行超时强制终止