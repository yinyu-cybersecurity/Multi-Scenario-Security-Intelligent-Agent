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