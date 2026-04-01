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