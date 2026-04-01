# Docker工具容器分离架构实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现Agent核心宿主机运行 + 安全工具Docker容器隔离执行的分离架构

**Architecture:** DockerToolExecutor作为工具调用路由层，高频工具使用持久容器池（ContainerPool管理），低频工具使用临时容器，Host网络模式直接访问目标网络

**Tech Stack:** Python 3.11, Docker SDK for Python, asyncio, dataclasses

---

## 文件结构

```
app/tools_v2/
├── docker_executor.py      # Docker执行器（新增）
├── container_pool.py       # 容器池管理（新增）
├── tool_images.py          # 工具镜像配置（新增）
└── tools/
    └── simple_tools.py     # 修改run_command()路由

docker/
├── web-tools/Dockerfile    # Web安全工具镜像
├── pwn-tools/Dockerfile    # Pwn工具镜像
├── ad-tools/Dockerfile     # AD域工具镜像
├── deser-tools/Dockerfile  # 反序列化工具镜像
└── misc-tools/Dockerfile   # 杂项工具镜像

config.yaml                 # 新增Docker配置
requirements.txt            # 新增docker依赖
README.md                   # 更新部署说明
```

---

### Task 1: 工具镜像配置模块

**Files:**
- Create: `app/tools_v2/tool_images.py`

- [ ] **Step 1: 创建工具镜像映射配置**

```python
# app/tools_v2/tool_images.py
"""
Docker工具镜像配置

定义工具到镜像的映射关系，以及容器池配置
"""

from typing import Dict, Any, Literal
from dataclasses import dataclass, field


@dataclass
class ToolImageConfig:
    """工具镜像配置"""
    image: str
    persistent: bool
    pool_name: str = ""
    timeout: int = 300


# 工具到镜像的映射
TOOL_IMAGE_MAPPING: Dict[str, ToolImageConfig] = {
    # === Web工具 - 高频持久容器 ===
    "nmap": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "nuclei": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "httpx": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "fscan": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "sqlmap": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "ffuf": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "dirsearch": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "xray": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "subfinder": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "gobuster": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "whatweb": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "hydra": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web", timeout=600),
    "dalfox": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    "httprobe": ToolImageConfig(image="ctf-tools-web", persistent=True, pool_name="web"),
    
    # === Pwn工具 - 高频持久容器 ===
    "binary_analyzer": ToolImageConfig(image="ctf-tools-pwn", persistent=True, pool_name="pwn"),
    "rop_builder": ToolImageConfig(image="ctf-tools-pwn", persistent=True, pool_name="pwn"),
    "shellcode_generator": ToolImageConfig(image="ctf-tools-pwn", persistent=True, pool_name="pwn"),
    
    # === AD域工具 - 低频临时容器 ===
    "crackmapexec": ToolImageConfig(image="ctf-tools-ad", persistent=False, timeout=600),
    "impacket": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "bloodhound": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "certipy": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "ldapdomaindump": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "pywhisker": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    "mimikatz": ToolImageConfig(image="ctf-tools-ad", persistent=False),
    
    # === 反序列化工具 - 低频临时容器 ===
    "ysoserial": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    "marshalsec": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    "jndiexploit": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    "phpggc": ToolImageConfig(image="ctf-tools-deser", persistent=False),
    
    # === 杂项工具 - 低频临时容器 ===
    "jwt_tool": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "ssrfmap": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "gopherus": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "githacker": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "binwalk": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "foremost": ToolImageConfig(image="ctf-tools-misc", persistent=False),
    "stegsolve": ToolImageConfig(image="ctf-tools-misc", persistent=False),
}


# 容器池配置
CONTAINER_POOL_CONFIG: Dict[str, Dict[str, Any]] = {
    "web": {
        "count": 3,
        "image": "ctf-tools-web:latest",
        "memory": "1g",
        "cpu_period": 100000,
        "cpu_quota": 50000,  # 50% CPU
    },
    "pwn": {
        "count": 2,
        "image": "ctf-tools-pwn:latest",
        "memory": "512m",
        "cpu_period": 100000,
        "cpu_quota": 30000,  # 30% CPU
    },
}


# 镜像构建配置
IMAGE_BUILD_CONFIG: Dict[str, Dict[str, Any]] = {
    "ctf-tools-web": {
        "dockerfile": "docker/web-tools/Dockerfile",
        "context": ".",
        "tools": ["nmap", "nuclei", "httpx", "fscan", "sqlmap", "ffuf", "dirsearch", 
                  "xray", "subfinder", "gobuster", "whatweb", "hydra", "dalfox", "httprobe"],
    },
    "ctf-tools-pwn": {
        "dockerfile": "docker/pwn-tools/Dockerfile",
        "context": ".",
        "tools": ["pwntools", "ROPgadget", "shellcode_generator"],
    },
    "ctf-tools-ad": {
        "dockerfile": "docker/ad-tools/Dockerfile",
        "context": ".",
        "tools": ["crackmapexec", "impacket", "bloodhound", "certipy", "mimikatz"],
    },
    "ctf-tools-deser": {
        "dockerfile": "docker/deser-tools/Dockerfile",
        "context": ".",
        "tools": ["ysoserial", "marshalsec", "JNDIExploit", "phpggc"],
    },
    "ctf-tools-misc": {
        "dockerfile": "docker/misc-tools/Dockerfile",
        "context": ".",
        "tools": ["jwt_tool", "ssrfmap", "gopherus", "githacker", "binwalk"],
    },
}


def get_tool_config(tool_name: str) -> ToolImageConfig | None:
    """获取工具配置"""
    return TOOL_IMAGE_MAPPING.get(tool_name)


def is_docker_tool(tool_name: str) -> bool:
    """检查工具是否应该用Docker执行"""
    return tool_name in TOOL_IMAGE_MAPPING


def get_pool_config(pool_name: str) -> Dict[str, Any] | None:
    """获取容器池配置"""
    return CONTAINER_POOL_CONFIG.get(pool_name)


def get_all_required_images() -> list[str]:
    """获取所有需要的镜像列表"""
    return list(set(config.image for config in TOOL_IMAGE_MAPPING.values()))
```

- [ ] **Step 2: 提交工具镜像配置**

```bash
git add app/tools_v2/tool_images.py
git commit -m "feat: 添加工具镜像配置模块"
```

---

### Task 2: 容器池管理模块

**Files:**
- Create: `app/tools_v2/container_pool.py`

- [ ] **Step 1: 创建容器池管理类**

```python
# app/tools_v2/container_pool.py
"""
Docker容器池管理

管理持久容器池的创建、获取、释放和清理
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import docker
from docker.models.containers import Container

from .tool_images import CONTAINER_POOL_CONFIG

logger = logging.getLogger(__name__)


@dataclass
class PooledContainer:
    """池化容器包装"""
    container: Container
    pool_name: str
    in_use: bool = False
    created_at: float = 0.0


class ContainerPool:
    """
    容器池管理器
    
    管理持久容器池，提供容器的获取和释放
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化容器池
        
        Args:
            config: 容器池配置，默认使用CONTAINER_POOL_CONFIG
        """
        self.config = config or CONTAINER_POOL_CONFIG
        self.client: Optional[docker.DockerClient] = None
        
        # 池状态
        # {pool_name: [PooledContainer, ...]}
        self.pools: Dict[str, list[PooledContainer]] = {}
        # {pool_name: asyncio.Queue}
        self.available: Dict[str, asyncio.Queue] = {}
        
        # 初始化状态
        self._initialized = False
        self._lock = asyncio.Lock()
    
    async def connect(self) -> bool:
        """
        连接Docker守护进程
        
        Returns:
            是否连接成功
        """
        try:
            # 在线程池中执行同步操作
            loop = asyncio.get_event_loop()
            self.client = await loop.run_in_executor(None, docker.from_env)
            
            # 测试连接
            await loop.run_in_executor(None, self.client.ping)
            logger.info("Docker连接成功")
            return True
            
        except docker.errors.DockerException as e:
            logger.error(f"Docker连接失败: {e}")
            self.client = None
            return False
    
    async def initialize(self) -> bool:
        """
        初始化持久容器池
        
        Returns:
            是否初始化成功
        """
        if self._initialized:
            return True
            
        if not self.client:
            if not await self.connect():
                return False
        
        try:
            for pool_name, pool_config in self.config.items():
                count = pool_config.get("count", 1)
                image = pool_config.get("image", "")
                
                # 初始化池和队列
                self.pools[pool_name] = []
                self.available[pool_name] = asyncio.Queue()
                
                # 创建容器
                for i in range(count):
                    container = await self._create_pool_container(
                        pool_name=pool_name,
                        image=image,
                        index=i,
                        config=pool_config
                    )
                    if container:
                        pooled = PooledContainer(
                            container=container,
                            pool_name=pool_name,
                            in_use=False
                        )
                        self.pools[pool_name].append(pooled)
                        await self.available[pool_name].put(pooled)
                        logger.info(f"创建容器池 {pool_name}#{i}")
            
            self._initialized = True
            logger.info(f"容器池初始化完成，共 {sum(len(p) for p in self.pools.values())} 个容器")
            return True
            
        except Exception as e:
            logger.error(f"容器池初始化失败: {e}")
            return False
    
    async def _create_pool_container(
        self,
        pool_name: str,
        image: str,
        index: int,
        config: Dict[str, Any]
    ) -> Optional[Container]:
        """
        创建池容器
        
        Args:
            pool_name: 池名称
            image: 镜像名
            index: 容器索引
            config: 容器配置
            
        Returns:
            容器对象或None
        """
        container_name = f"ctf-{pool_name}-{index}"
        
        try:
            loop = asyncio.get_event_loop()
            
            # 检查镜像是否存在
            try:
                await loop.run_in_executor(
                    None,
                    lambda: self.client.images.get(image)
                )
            except docker.errors.ImageNotFound:
                logger.warning(f"镜像 {image} 不存在，请先构建")
                return None
            
            # 创建容器
            container = await loop.run_in_executor(
                None,
                lambda: self.client.containers.create(
                    image=image,
                    name=container_name,
                    network_mode="host",  # Host网络模式
                    detach=True,
                    auto_remove=False,
                    # 资源限制
                    mem_limit=config.get("memory", "512m"),
                    cpu_period=config.get("cpu_period", 100000),
                    cpu_quota=config.get("cpu_quota", 50000),
                    # 安全配置
                    privileged=False,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges"],
                )
            )
            
            # 启动容器
            await loop.run_in_executor(None, container.start)
            
            return container
            
        except Exception as e:
            logger.error(f"创建容器 {container_name} 失败: {e}")
            return None
    
    async def acquire(self, pool_name: str, timeout: float = 10.0) -> Optional[PooledContainer]:
        """
        获取可用容器
        
        Args:
            pool_name: 池名称
            timeout: 等待超时（秒）
            
        Returns:
            池化容器或None
        """
        if pool_name not in self.available:
            logger.error(f"未知的池名称: {pool_name}")
            return None
        
        try:
            # 等待可用容器
            pooled = await asyncio.wait_for(
                self.available[pool_name].get(),
                timeout=timeout
            )
            pooled.in_use = True
            return pooled
            
        except asyncio.TimeoutError:
            logger.warning(f"获取容器超时: {pool_name}")
            return None
    
    def release(self, pooled: PooledContainer):
        """
        释放容器回池
        
        Args:
            pooled: 池化容器
        """
        if not pooled or not pooled.pool_name:
            return
        
        pooled.in_use = False
        
        if pooled.pool_name in self.available:
            # 使用同步方式放入队列（队列操作是线程安全的）
            self.available[pooled.pool_name].put_nowait(pooled)
    
    async def cleanup(self):
        """
        清理容器池
        """
        if not self.client:
            return
        
        loop = asyncio.get_event_loop()
        
        for pool_name, containers in self.pools.items():
            for pooled in containers:
                try:
                    if pooled.container:
                        await loop.run_in_executor(None, pooled.container.stop)
                        await loop.run_in_executor(None, pooled.container.remove)
                        logger.info(f"清理容器: {pooled.container.name}")
                except Exception as e:
                    logger.error(f"清理容器失败: {e}")
        
        self.pools.clear()
        self.available.clear()
        self._initialized = False
    
    async def health_check(self) -> Dict[str, Any]:
        """
        健康检查
        
        Returns:
            健康状态
        """
        status = {
            "docker_connected": self.client is not None,
            "pools": {},
            "total_containers": 0,
            "available_containers": 0,
        }
        
        for pool_name, containers in self.pools.items():
            available = sum(1 for c in containers if not c.in_use)
            status["pools"][pool_name] = {
                "total": len(containers),
                "available": available,
            }
            status["total_containers"] += len(containers)
            status["available_containers"] += available
        
        return status


# 全局容器池实例
_container_pool: Optional[ContainerPool] = None


def get_container_pool() -> ContainerPool:
    """获取全局容器池实例"""
    global _container_pool
    if _container_pool is None:
        _container_pool = ContainerPool()
    return _container_pool
```

- [ ] **Step 2: 提交容器池管理模块**

```bash
git add app/tools_v2/container_pool.py
git commit -m "feat: 添加容器池管理模块"
```

---

### Task 3: Docker执行器模块

**Files:**
- Create: `app/tools_v2/docker_executor.py`

- [ ] **Step 1: 创建Docker执行器**

```python
# app/tools_v2/docker_executor.py
"""
Docker工具执行器

统一管理工具在Docker容器中的执行
"""

import asyncio
import logging
from typing import Dict, Any, Optional
import docker
from docker.models.containers import Container

from .container_pool import ContainerPool, get_container_pool, PooledContainer
from .tool_images import get_tool_config, is_docker_tool

logger = logging.getLogger(__name__)


class DockerToolExecutor:
    """
    Docker工具执行器
    
    负责在Docker容器中执行安全工具
    """
    
    def __init__(
        self,
        pool: ContainerPool = None,
        fallback_to_local: bool = True,
        default_timeout: int = 300
    ):
        """
        初始化执行器
        
        Args:
            pool: 容器池实例
            fallback_to_local: Docker不可用时是否降级本地执行
            default_timeout: 默认超时时间
        """
        self.pool = pool or get_container_pool()
        self.fallback_to_local = fallback_to_local
        self.default_timeout = default_timeout
        self.client: Optional[docker.DockerClient] = None
        self._initialized = False
    
    async def initialize(self) -> bool:
        """
        初始化执行器
        
        Returns:
            是否初始化成功
        """
        if self._initialized:
            return True
        
        # 尝试连接Docker
        try:
            loop = asyncio.get_event_loop()
            self.client = await loop.run_in_executor(None, docker.from_env)
            await loop.run_in_executor(None, self.client.ping)
            
            # 初始化容器池
            pool_ok = await self.pool.initialize()
            
            if pool_ok:
                self._initialized = True
                logger.info("DockerToolExecutor初始化成功")
                return True
            else:
                logger.warning("容器池初始化失败，将使用降级模式")
                self._initialized = False
                return False
                
        except docker.errors.DockerException as e:
            logger.warning(f"Docker不可用: {e}")
            self.client = None
            return False
    
    async def execute(
        self,
        tool_name: str,
        command: list,
        timeout: int = None,
        volume_mounts: Dict[str, str] = None,
        env_vars: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        执行工具命令
        
        Args:
            tool_name: 工具名称
            command: 命令列表
            timeout: 超时时间（秒）
            volume_mounts: 卷挂载 {容器路径: 宿主机路径}
            env_vars: 环境变量
            
        Returns:
            {"success": bool, "stdout": str, "stderr": str, ...}
        """
        timeout = timeout or self.default_timeout
        
        # 获取工具配置
        tool_config = get_tool_config(tool_name)
        if not tool_config:
            return {
                "success": False,
                "error": f"工具 {tool_name} 未配置Docker镜像"
            }
        
        # 尝试Docker执行
        if self._initialized and self.client:
            try:
                if tool_config.persistent:
                    return await self._execute_persistent(tool_config, command, timeout)
                else:
                    return await self._execute_temporary(tool_config, command, timeout, volume_mounts, env_vars)
                    
            except docker.errors.DockerException as e:
                logger.error(f"Docker执行失败: {e}")
                if self.fallback_to_local:
                    return await self._fallback_local(command, timeout)
                return {"success": False, "error": f"Docker错误: {e}"}
        else:
            # Docker不可用，降级本地执行
            if self.fallback_to_local:
                return await self._fallback_local(command, timeout)
            return {"success": False, "error": "Docker不可用"}
    
    async def _execute_persistent(
        self,
        tool_config,
        command: list,
        timeout: int
    ) -> Dict[str, Any]:
        """
        使用持久容器执行
        """
        pool_name = tool_config.pool_name
        pooled: Optional[PooledContainer] = await self.pool.acquire(pool_name, timeout=5)
        
        if not pooled:
            # 池耗尽，创建临时容器
            logger.warning(f"容器池 {pool_name} 耗尽，使用临时容器")
            return await self._execute_temporary(tool_config, command, timeout)
        
        try:
            # 执行命令
            loop = asyncio.get_event_loop()
            exit_code, output = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: pooled.container.exec_run(
                        cmd=command,
                        demux=True,  # 分离stdout和stderr
                    )
                ),
                timeout=timeout
            )
            
            stdout = output[0].decode('utf-8', errors='replace') if output[0] else ""
            stderr = output[1].decode('utf-8', errors='replace') if output[1] else ""
            
            return {
                "success": exit_code == 0,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "container_id": pooled.container.id[:12],
            }
            
        except asyncio.TimeoutError:
            logger.error(f"容器执行超时: {command[0]}")
            return {"success": False, "error": "执行超时"}
            
        finally:
            self.pool.release(pooled)
    
    async def _execute_temporary(
        self,
        tool_config,
        command: list,
        timeout: int,
        volume_mounts: Dict[str, str] = None,
        env_vars: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        使用临时容器执行
        """
        container = None
        try:
            loop = asyncio.get_event_loop()
            
            # 准备卷挂载
            volumes = {}
            if volume_mounts:
                for container_path, host_path in volume_mounts.items():
                    volumes[host_path] = {"bind": container_path, "mode": "rw"}
            
            # 创建临时容器
            container = await loop.run_in_executor(
                None,
                lambda: self.client.containers.create(
                    image=tool_config.image,
                    command=command,
                    network_mode="host",
                    volumes=volumes,
                    environment=env_vars,
                    detach=True,
                    auto_remove=False,
                    privileged=False,
                    cap_drop=["ALL"],
                )
            )
            
            # 启动并等待
            await loop.run_in_executor(None, container.start)
            
            result = await loop.run_in_executor(
                None,
                lambda: container.wait(timeout=timeout)
            )
            
            # 获取输出
            logs = await loop.run_in_executor(
                None,
                lambda: container.logs(stdout=True, stderr=True)
            )
            
            return {
                "success": result.get("StatusCode", -1) == 0,
                "stdout": logs.decode('utf-8', errors='replace'),
                "stderr": "",
                "exit_code": result.get("StatusCode", -1),
                "container_id": container.id[:12],
            }
            
        except asyncio.TimeoutError:
            if container:
                await loop.run_in_executor(None, container.stop)
            return {"success": False, "error": "执行超时"}
            
        except docker.errors.ImageNotFound:
            return {
                "success": False,
                "error": f"镜像 {tool_config.image} 不存在，请先构建:\n  docker build -t {tool_config.image} -f docker/{tool_config.pool_name}-tools/Dockerfile ."
            }
            
        finally:
            if container:
                try:
                    await loop.run_in_executor(None, container.remove, True)
                except:
                    pass
    
    async def _fallback_local(self, command: list, timeout: int) -> Dict[str, Any]:
        """
        降级到本地执行
        """
        logger.warning(f"降级到本地执行: {command[0]}")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            
            return {
                "success": proc.returncode == 0,
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "fallback": True,
            }
            
        except asyncio.TimeoutError:
            return {"success": False, "error": "本地执行超时"}
        except FileNotFoundError:
            return {"success": False, "error": f"工具未安装: {command[0]}"}
        except Exception as e:
            return {"success": False, "error": f"本地执行失败: {e}"}
    
    async def cleanup(self):
        """清理资源"""
        await self.pool.cleanup()


# 全局执行器实例
_executor: Optional[DockerToolExecutor] = None


def get_docker_executor() -> DockerToolExecutor:
    """获取全局执行器实例"""
    global _executor
    if _executor is None:
        _executor = DockerToolExecutor()
    return _executor


async def initialize_docker_executor() -> bool:
    """初始化全局执行器"""
    executor = get_docker_executor()
    return await executor.initialize()
```

- [ ] **Step 2: 提交Docker执行器模块**

```bash
git add app/tools_v2/docker_executor.py
git commit -m "feat: 添加Docker工具执行器模块"
```

---

### Task 4: 修改工具调用路由

**Files:**
- Modify: `app/tools_v2/tools/simple_tools.py`

- [ ] **Step 1: 修改run_command函数**

在 `simple_tools.py` 中找到 `run_command` 函数（约第947行），将其修改为：

```python
async def run_command(
    cmd: list,
    timeout: int = 300,
    interactive: bool = False,
    inputs: list = None,
    use_docker: bool = True  # 新增参数
) -> Dict[str, Any]:
    """执行命令并返回结果

    Args:
        cmd: 命令列表
        timeout: 超时时间（秒）
        interactive: 是否需要交互式输入
        inputs: 自动输入列表（按顺序发送给进程）
        use_docker: 是否尝试Docker执行

    Returns:
        包含success, stdout, stderr的字典
    """
    from ..tool_images import is_docker_tool
    from ..docker_executor import get_docker_executor
    
    tool_name = cmd[0] if cmd else None
    
    # 检查是否应该用Docker执行
    if use_docker and tool_name and is_docker_tool(tool_name):
        executor = get_docker_executor()
        return await executor.execute(
            tool_name=tool_name,
            command=cmd,
            timeout=timeout
        )
    
    # 本地执行（降级模式或非Docker工具）
    return await _run_local_command(cmd, timeout, interactive, inputs)


async def _run_local_command(
    cmd: list,
    timeout: int = 300,
    interactive: bool = False,
    inputs: list = None
) -> Dict[str, Any]:
    """本地执行命令（原run_command的逻辑）"""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if (interactive or inputs) else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # 如果有预设输入，自动发送
        if inputs:
            input_data = '\n'.join(inputs) + '\n'
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input_data.encode()),
                timeout=timeout
            )
        else:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )

        return {
            "success": proc.returncode == 0,
            "stdout": stdout.decode('utf-8', errors='replace'),
            "stderr": stderr.decode('utf-8', errors='replace')
        }
    except asyncio.TimeoutError:
        return {"success": False, "error": "超时"}
    except FileNotFoundError:
        return {"success": False, "error": f"工具未安装: {cmd[0] if cmd else 'unknown'}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

- [ ] **Step 2: 提交工具调用路由修改**

```bash
git add app/tools_v2/tools/simple_tools.py
git commit -m "feat: 修改run_command支持Docker容器执行"
```

---

### Task 5: 更新配置模块

**Files:**
- Modify: `app/config.py`

- [ ] **Step 1: 在Config类中添加Docker配置**

在 `app/config.py` 的 `Config` 类中添加（约第410行后）：

```python
    # =========================================================================
    # Docker配置 - 工具容器化
    # =========================================================================
    
    # Docker是否启用
    DOCKER_ENABLED: bool = True
    
    # Docker不可用时降级本地执行
    DOCKER_FALLBACK_TO_LOCAL: bool = True
    
    # 容器池配置
    DOCKER_CONTAINER_POOLS: Dict[str, int] = field(default_factory=lambda: {
        "web": 3,
        "pwn": 2,
    })
    
    # Docker超时配置
    DOCKER_CONTAINER_START_TIMEOUT: int = 30
    DOCKER_EXECUTION_TIMEOUT: int = 300
    
    # Docker资源限制
    DOCKER_MEMORY_LIMIT: str = "1g"
    DOCKER_CPU_QUOTA: int = 50000  # 50%
```

- [ ] **Step 2: 提交配置更新**

```bash
git add app/config.py
git commit -m "feat: 添加Docker工具容器配置项"
```

---

### Task 6: 更新配置文件示例

**Files:**
- Modify: `config.yaml.example`

- [ ] **Step 1: 添加Docker配置**

```yaml
# ===== Docker Configuration =====
# 工具容器化配置
DOCKER_ENABLED: true
DOCKER_FALLBACK_TO_LOCAL: true  # Docker不可用时降级本地执行

# 容器池大小
DOCKER_CONTAINER_POOLS:
  web: 3  # Web工具持久容器数
  pwn: 2  # Pwn工具持久容器数

# Docker超时（秒）
DOCKER_CONTAINER_START_TIMEOUT: 30
DOCKER_EXECUTION_TIMEOUT: 300

# Docker资源限制
DOCKER_MEMORY_LIMIT: "1g"
DOCKER_CPU_QUOTA: 50000  # 50% CPU
```

- [ ] **Step 2: 提交配置文件更新**

```bash
git add config.yaml.example
git commit -m "feat: 更新配置文件示例添加Docker配置"
```

---

### Task 7: 更新依赖

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: 添加Docker SDK依赖**

在 `requirements.txt` 中添加：

```
# Docker SDK
docker>=7.0.0
```

- [ ] **Step 2: 提交依赖更新**

```bash
git add requirements.txt
git commit -m "feat: 添加Docker SDK依赖"
```

---

### Task 8: 创建Web工具镜像

**Files:**
- Create: `docker/web-tools/Dockerfile`

- [ ] **Step 1: 创建Web工具Dockerfile**

```dockerfile
# CTF Web安全工具镜像
# 包含: nmap, nuclei, httpx, fscan, sqlmap, ffuf, dirsearch, xray等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl wget git unzip \
    libssl-dev libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Go环境
RUN wget -q https://mirrors.aliyun.com/golang/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$PATH:/root/go/bin
ENV GOPROXY=https://goproxy.cn,direct

# Go工具
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest

# Python工具
RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

RUN pipx install sqlmap || true

# 其他工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    whatweb hydra \
    && rm -rf /var/lib/apt/lists/*

# fscan
RUN wget -q -O /usr/local/bin/fscan https://github.com/shadow1ng/fscan/releases/download/1.8.2/fscan && \
    chmod +x /usr/local/bin/fscan || true

# xray
RUN wget -q -O /usr/local/bin/xray https://github.com/chaitin/xray/releases/download/1.9.11/xray_linux_amd64.zip && \
    unzip /usr/local/bin/xray -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/xray || true

# dirsearch
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch && \
    pip install -r /opt/dirsearch/requirements.txt && \
    ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

# 工作目录
WORKDIR /workspace

# 默认命令
CMD ["sleep", "infinity"]
```

- [ ] **Step 2: 提交Web工具镜像**

```bash
git add docker/web-tools/Dockerfile
git commit -m "feat: 添加Web工具Docker镜像"
```

---

### Task 9: 创建Pwn工具镜像

**Files:**
- Create: `docker/pwn-tools/Dockerfile`

- [ ] **Step 1: 创建Pwn工具Dockerfile**

```dockerfile
# CTF Pwn工具镜像
# 包含: pwntools, ROPgadget, pwndbg等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb gdb-multiarch \
    libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

# Python Pwn工具
RUN pip install --no-cache-dir \
    pwntools \
    ROPgadget \
    capstone \
    keystone-engine \
    unicorn

# pwndbg
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg.git /opt/pwndbg && \
    cd /opt/pwndbg && ./setup.sh || true

# 工作目录
WORKDIR /workspace

CMD ["sleep", "infinity"]
```

- [ ] **Step 2: 提交Pwn工具镜像**

```bash
git add docker/pwn-tools/Dockerfile
git commit -m "feat: 添加Pwn工具Docker镜像"
```

---

### Task 10: 创建AD工具镜像

**Files:**
- Create: `docker/ad-tools/Dockerfile`

- [ ] **Step 1: 创建AD工具Dockerfile**

```dockerfile
# CTF AD域工具镜像
# 包含: crackmapexec, impacket, bloodhound, certipy等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# 基础依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libkrb5-dev \
    libffi-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python工具
RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

RUN pipx install crackmapexec || true
RUN pipx install impacket || true
RUN pipx install bloodhound || true
RUN pipx install certipy-ad || true
RUN pipx install ldapdomaindump || true
RUN pipx install pywhisker || true

# 工作目录
WORKDIR /workspace

CMD ["sleep", "infinity"]
```

- [ ] **Step 2: 提交AD工具镜像**

```bash
git add docker/ad-tools/Dockerfile
git commit -m "feat: 添加AD域工具Docker镜像"
```

---

### Task 11: 创建反序列化工具镜像

**Files:**
- Create: `docker/deser-tools/Dockerfile`

- [ ] **Step 1: 创建反序列化工具Dockerfile**

```dockerfile
# CTF反序列化工具镜像
# 包含: ysoserial, marshalsec, JNDIExploit, phpggc

FROM openjdk:11-jdk-slim

ENV DEBIAN_FRONTEND=noninteractive

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    git maven python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# 工作目录
WORKDIR /tools

# ysoserial
RUN wget -q -O /tools/ysoserial.jar https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar || true

# JNDIExploit
RUN git clone --depth 1 https://github.com/welk1n/JNDI-Injection-Exploit.git /tools/JNDIExploit && \
    cd /tools/JNDIExploit && mvn clean package -DskipTests || true

# marshalsec
RUN git clone --depth 1 https://github.com/mbechler/marshalsec.git /tools/marshalsec && \
    cd /tools/marshalsec && mvn clean package -DskipTests || true

# phpggc
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /tools/phpggc

WORKDIR /workspace

CMD ["sleep", "infinity"]
```

- [ ] **Step 2: 提交反序列化工具镜像**

```bash
git add docker/deser-tools/Dockerfile
git commit -m "feat: 添加反序列化工具Docker镜像"
```

---

### Task 12: 创建杂项工具镜像

**Files:**
- Create: `docker/misc-tools/Dockerfile`

- [ ] **Step 1: 创建杂项工具Dockerfile**

```dockerfile
# CTF杂项工具镜像
# 包含: jwt_tool, ssrfmap, gopherus, githacker, binwalk等

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk foremost exiftool \
    && rm -rf /var/lib/apt/lists/*

# Python工具
RUN pip install --no-cache-dir pipx && pipx ensurepath
ENV PATH="/root/.local/bin:$PATH"

# jwt_tool
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip install -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# SSRFmap
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/ssrfmap && \
    pip install -r /opt/ssrfmap/requirements.txt

# Gopherus
RUN git clone --depth 1 https://github.com/tarunkant/Gopherus.git /opt/gopherus && \
    cd /opt/gopherus && ./install.sh || true

# GitHacker
RUN pipx install githacker || true

WORKDIR /workspace

CMD ["sleep", "infinity"]
```

- [ ] **Step 2: 提交杂项工具镜像**

```bash
git add docker/misc-tools/Dockerfile
git commit -m "feat: 添加杂项工具Docker镜像"
```

---

### Task 13: 更新模块导出

**Files:**
- Modify: `app/tools_v2/__init__.py`

- [ ] **Step 1: 更新__init__.py导出**

```python
# Tools V2系统
#
# 借鉴Claude Code的buildTool工厂设计

from .tool_factory import (
    # 核心类
    CTFToolV2,
    ToolSchema,
    ParamSchema,
    ParamType,
    ValidationResult,
    ToolExecutionResult,
    ZodValidator,

    # 工厂函数
    buildTool,
    ensure_result_format,

    # 注册表
    ToolRegistryV2,
    get_tool_registry_v2,
    register_tool,
)

from .concurrency_config import (
    ConcurrencyLevel,
    ToolConcurrencyConfig,
    is_concurrency_safe,
    get_max_concurrent,
    classify_tools_for_parallel,
    is_read_only_command,
)

# Docker工具容器支持
from .tool_images import (
    ToolImageConfig,
    TOOL_IMAGE_MAPPING,
    CONTAINER_POOL_CONFIG,
    get_tool_config,
    is_docker_tool,
    get_pool_config,
    get_all_required_images,
)

from .container_pool import (
    ContainerPool,
    PooledContainer,
    get_container_pool,
)

from .docker_executor import (
    DockerToolExecutor,
    get_docker_executor,
    initialize_docker_executor,
)

__all__ = [
    # 核心类
    "CTFToolV2",
    "ToolSchema",
    "ParamSchema",
    "ParamType",
    "ValidationResult",
    "ToolExecutionResult",
    "ZodValidator",

    # 工厂函数
    "buildTool",
    "ensure_result_format",

    # 注册表
    "ToolRegistryV2",
    "get_tool_registry_v2",
    "register_tool",

    # 并发安全
    "ConcurrencyLevel",
    "ToolConcurrencyConfig",
    "is_concurrency_safe",
    "get_max_concurrent",
    "classify_tools_for_parallel",
    "is_read_only_command",

    # Docker工具容器
    "ToolImageConfig",
    "TOOL_IMAGE_MAPPING",
    "CONTAINER_POOL_CONFIG",
    "get_tool_config",
    "is_docker_tool",
    "get_pool_config",
    "get_all_required_images",
    "ContainerPool",
    "PooledContainer",
    "get_container_pool",
    "DockerToolExecutor",
    "get_docker_executor",
    "initialize_docker_executor",
]
```

- [ ] **Step 2: 提交模块导出更新**

```bash
git add app/tools_v2/__init__.py
git commit -m "feat: 更新tools_v2模块导出添加Docker支持"
```

---

### Task 14: 更新README文档

**Files:**
- Modify: `README.md`

- [ ] **Step 1: 更新README添加Docker部署说明**

在README.md的部署部分添加：

```markdown
## 快速开始

### 本地运行 + Docker工具容器（推荐）

```bash
# 1. 安装Python依赖
pip install -r requirements.txt

# 2. 构建Docker工具镜像
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
```

- [ ] **Step 2: 提交README更新**

```bash
git add README.md
git commit -m "docs: 更新README添加Docker工具容器部署说明"
```

---

### Task 15: 创建镜像构建脚本

**Files:**
- Create: `scripts/build-images.sh`

- [ ] **Step 1: 创建构建脚本**

```bash
#!/bin/bash
# 构建所有Docker工具镜像

set -e

echo "=== 构建CTF工具Docker镜像 ==="

# 镜像列表
IMAGES=(
    "web-tools:ctf-tools-web"
    "pwn-tools:ctf-tools-pwn"
    "ad-tools:ctf-tools-ad"
    "deser-tools:ctf-tools-deser"
    "misc-tools:ctf-tools-misc"
)

# 构建每个镜像
for item in "${IMAGES[@]}"; do
    IFS=':' read -r dir name <<< "$item"
    echo ""
    echo "--- 构建 $name ---"
    docker build -t "${name}:latest" -f "docker/${dir}/Dockerfile" .
done

echo ""
echo "=== 构建完成 ==="
echo "镜像列表:"
docker images | grep ctf-tools
```

- [ ] **Step 2: 设置执行权限并提交**

```bash
chmod +x scripts/build-images.sh
git add scripts/build-images.sh
git commit -m "feat: 添加Docker镜像构建脚本"
```

---

### Task 16: 清理旧Dockerfile

**Files:**
- Delete: `Dockerfile` (根目录)

- [ ] **Step 1: 移除旧的统一Dockerfile**

旧的Dockerfile是整体部署模式，已被新的分离架构取代。

```bash
git rm Dockerfile
git commit -m "refactor: 移除旧的统一Dockerfile，使用分离架构"
```

---

### Task 17: 最终验证与提交

- [ ] **Step 1: 运行代码检查**

```bash
# 检查Python语法
python -m py_compile app/tools_v2/tool_images.py
python -m py_compile app/tools_v2/container_pool.py
python -m py_compile app/tools_v2/docker_executor.py
```

- [ ] **Step 2: 检查所有更改**

```bash
git status
git diff --stat
```

- [ ] **Step 3: 最终提交**

```bash
git add -A
git commit -m "feat: 完成Docker工具容器分离架构

- 新增 DockerToolExecutor 和 ContainerPool 模块
- 新增 tool_images 工具镜像配置
- 修改 run_command() 支持Docker容器执行
- 创建5个分类工具镜像Dockerfile
- 更新配置、依赖、README文档
- 移除旧的统一Dockerfile

架构特点:
- Agent核心在宿主机运行
- 安全工具在Docker容器隔离执行
- 高频工具使用持久容器池
- 低频工具使用临时容器
- Host网络模式直接访问目标网络
- Docker不可用时自动降级本地执行"
```

---

## 验收清单

- [ ] `tool_images.py` 正确映射所有工具
- [ ] `container_pool.py` 容器池管理正常
- [ ] `docker_executor.py` 执行路由正确
- [ ] `run_command()` 正确路由到Docker
- [ ] 5个Dockerfile构建成功
- [ ] `requirements.txt` 包含docker依赖
- [ ] `config.yaml.example` 包含Docker配置
- [ ] `README.md` 更新部署说明
- [ ] 旧Dockerfile已移除
- [ ] 代码无语法错误