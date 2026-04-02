#!/usr/bin/env python3
"""
HTTP Client - 同步/异步 HTTP 客户端
"""

import asyncio
import time
from typing import Dict, Optional, Any, Callable
from dataclasses import dataclass
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class HTTPClientConfig:
    """HTTP 客户端配置"""
    max_concurrent: int = 50
    max_retries: int = 3
    timeout: int = 30
    proxy: Optional[str] = None
    verify_ssl: bool = True
    retry_backoff: float = 0.5


class HTTPClient:
    """
    HTTP 客户端
    
    功能:
    - 同步/异步请求
    - 并发控制
    - 重试机制
    - 代理支持
    """
    
    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()
        self.session = self._create_session()
        self._semaphore: Optional[asyncio.Semaphore] = None
    
    def _create_session(self) -> requests.Session:
        """创建 requests session"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=self.config.max_concurrent)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        if self.config.proxy:
            session.proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy,
            }
        
        return session
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """GET 请求"""
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """POST 请求"""
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        return self.session.post(url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        """PUT 请求"""
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        return self.session.put(url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """DELETE 请求"""
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        return self.session.delete(url, **kwargs)
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """通用请求"""
        kwargs.setdefault('timeout', self.config.timeout)
        kwargs.setdefault('verify', self.config.verify_ssl)
        return self.session.request(method, url, **kwargs)
    
    def batch_request(self, urls: list, method: str = 'GET', **kwargs) -> Dict[str, requests.Response]:
        """批量请求"""
        import concurrent.futures
        
        results = {}
        
        def fetch(url):
            try:
                resp = self.request(method, url, **kwargs)
                return url, resp
            except Exception as e:
                return url, None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_concurrent) as executor:
            futures = {executor.submit(fetch, url): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                url, resp = future.result()
                results[url] = resp
        
        return results


class AsyncHTTPClient:
    """
    异步 HTTP 客户端
    """
    
    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
    
    async def _get_session(self) -> 'aiohttp.ClientSession':
        """获取或创建 session"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                }
            )
        return self._session
    
    async def get(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """GET 请求"""
        session = await self._get_session()
        async with self._semaphore:
            return await session.get(url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """POST 请求"""
        session = await self._get_session()
        async with self._semaphore:
            return await session.post(url, **kwargs)
    
    async def request(self, method: str, url: str, **kwargs) -> 'aiohttp.ClientResponse':
        """通用请求"""
        session = await self._get_session()
        async with self._semaphore:
            return await session.request(method, url, **kwargs)
    
    async def batch_request(self, urls: list, method: str = 'GET', **kwargs) -> Dict[str, Any]:
        """批量请求"""
        tasks = [self.request(method, url, **kwargs) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        return dict(zip(urls, responses))
    
    async def close(self):
        """关闭 session"""
        if self._session and not self._session.closed:
            await self._session.close()


try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
