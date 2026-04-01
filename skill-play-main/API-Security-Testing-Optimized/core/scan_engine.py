#!/usr/bin/env python3
"""
ScanEngine - 统一扫描引擎
提供 Collector → Analyzer → Tester 的三阶段 Pipeline 架构
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from .collectors import JSCollector, ApiPathFinder, URLCollector, BrowserCollectorFacade, JSFingerprintCache
except ImportError:
    from collectors import JSCollector, ApiPathFinder, URLCollector, BrowserCollectorFacade, JSFingerprintCache
from .models import APIEndpoint, Vulnerability, ScanResult, Severity

logger = logging.getLogger(__name__)


class ScanStage(Enum):
    """扫描阶段"""
    COLLECT = "collect"
    ANALYZE = "analyze"
    TEST = "test"
    REPORT = "report"


@dataclass
class ScanEngineConfig:
    """扫描引擎配置"""
    target: str
    concurrency: int = 50
    timeout: int = 30
    js_depth: int = 3
    cookies: str = ""
    proxy: Optional[str] = None
    verify_ssl: bool = True
    output_dir: str = "./results"
    
    # 各阶段开关
    enable_js_collect: bool = True
    enable_api_collect: bool = True
    enable_browser_collect: bool = True
    enable_sqli_test: bool = True
    enable_xss_test: bool = True
    enable_idor_test: bool = True
    enable_info_test: bool = True
    
    # 评分阈值
    high_value_threshold: int = 5


@dataclass
class ScanProgress:
    """扫描进度"""
    stage: ScanStage
    phase: str
    total_apis: int = 0
    alive_apis: int = 0
    high_value_apis: int = 0
    vulnerabilities: int = 0
    start_time: float = field(default_factory=time.time)
    
    def elapsed(self) -> float:
        return time.time() - self.start_time
    
    def to_dict(self) -> Dict:
        return {
            'stage': self.stage.value,
            'phase': self.phase,
            'total_apis': self.total_apis,
            'alive_apis': self.alive_apis,
            'high_value_apis': self.high_value_apis,
            'vulnerabilities': self.vulnerabilities,
            'elapsed_seconds': round(self.elapsed(), 2)
        }


class ScanEngine:
    """
    统一扫描引擎
    
    三阶段 Pipeline:
    ┌─────────────────────────────────────────────────────────────┐
    │  Stage 1: COLLECT (采集)                                    │
    │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐│
    │  │ JS采集     │→ │ API发现   │→ │ URL采集   │→ │ 浏览器采集││
    │  │ (递归深度3)│  │ (25+正则) │  │ (域名/Base│  │ (动态渲染││
    │  └───────────┘  └───────────┘  └───────────┘  └───────────┘│
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Stage 2: ANALYZE (分析)                                   │
    │  ┌───────────┐  ┌───────────┐  ┌───────────┐               │
    │  │ HTTP探测  │→ │ API评分   │→ │ 敏感信息  │               │
    │  │ (验证存活)│  │ (高价值)  │  │ 检测      │               │
    │  └───────────┘  └───────────┘  └───────────┘               │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Stage 3: TEST (测试)                                      │
    │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐│
    │  │ SQL注入   │→ │ XSS测试  │→ │ IDOR测试  │→ │ 信息泄露  ││
    │  └───────────┘  └───────────┘  └───────────┘  └───────────┘│
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, config: ScanEngineConfig):
        self.config = config
        self.session = requests.Session() if HAS_REQUESTS else None
        
        self._js_cache: Optional[JSFingerprintCache] = None
        self._js_collector: Optional[JSCollector] = None
        self._api_finder: Optional[ApiPathFinder] = None
        self._url_collector: Optional[URLCollector] = None
        self._browser_collector: Optional[BrowserCollectorFacade] = None
        
        self.progress = ScanProgress(stage=ScanStage.COLLECT, phase="init")
        self.result: Optional[ScanResult] = None
        
        self._callbacks: Dict[str, List[Callable]] = {
            'stage_start': [],
            'stage_progress': [],
            'stage_complete': [],
            'finding': [],
        }
        
        self._running = False
    
    def on(self, event: str, callback: Callable):
        """注册事件回调"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any):
        """触发事件"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.warning(f"Callback error for {event}: {e}")
    
    def _update_progress(self, stage: ScanStage, phase: str, **kwargs):
        """更新进度"""
        self.progress.stage = stage
        self.progress.phase = phase
        for key, value in kwargs.items():
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)
        self._emit('stage_progress', self.progress.to_dict())
    
    async def initialize(self):
        """初始化扫描引擎"""
        self._running = True
        
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            if self.config.cookies:
                self.session.headers['Cookie'] = self.config.cookies
        
        self._js_collector = JSCollector(session=self.session, max_depth=self.config.js_depth)
        self._api_finder = ApiPathFinder()
        self._url_collector = URLCollector(session=self.session)
        self._browser_collector = BrowserCollectorFacade(headless=True)
        
        self.result = ScanResult(
            target_url=self.config.target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    async def run(self) -> ScanResult:
        """运行完整扫描流程"""
        await self.initialize()
        
        try:
            # Stage 1: 采集
            self._emit('stage_start', {'stage': 'collect'})
            self._update_progress(ScanStage.COLLECT, 'js_collection')
            await self._run_collectors()
            self._emit('stage_complete', {'stage': 'collect'})
            
            # Stage 2: 分析
            self._emit('stage_start', {'stage': 'analyze'})
            self._update_progress(ScanStage.ANALYZE, 'api_scoring')
            await self._run_analyzers()
            self._emit('stage_complete', {'stage': 'analyze'})
            
            # Stage 3: 测试
            if self.result and self.result.api_endpoints:
                self._emit('stage_start', {'stage': 'test'})
                self._update_progress(ScanStage.TEST, 'vulnerability_testing')
                await self._run_testers()
                self._emit('stage_complete', {'stage': 'test'})
            
            # Stage 4: 报告
            self._emit('stage_start', {'stage': 'report'})
            self._update_progress(ScanStage.REPORT, 'report_generation')
            self._emit('stage_complete', {'stage': 'report'})
            
            if self.result:
                self.result.status = "completed"
                
        except Exception as e:
            logger.error(f"Scan error: {e}")
            if self.result:
                self.result.errors.append(str(e))
                self.result.status = "failed"
        
        return self.result or ScanResult(target_url=self.config.target)
    
    async def _run_collectors(self):
        """运行采集阶段"""
        collected_js = []
        collected_apis = []
        
        try:
            resp = self.session.get(self.config.target, timeout=self.config.timeout)
            html = resp.text
        except Exception as e:
            logger.error(f"Failed to fetch target: {e}")
            html = ""
        
        # JS 采集
        if self.config.enable_js_collect and html:
            self._update_progress(ScanStage.COLLECT, phase='js_collect')
            
            js_urls = self._js_collector.extract_js_from_html(html, self.config.target)
            logger.info(f"Found {len(js_urls)} JS files in HTML")
            
            for js_url in js_urls[:20]:
                try:
                    js_resp = self.session.get(js_url, timeout=self.config.timeout)
                    if js_resp.status_code == 200:
                        content = js_resp.text
                        collected_js.append({'url': js_url, 'content': content})
                        
                        apis = self._api_finder.find_api_paths_in_text(content, js_url)
                        collected_apis.extend(apis)
                        
                        self._js_collector.parse_js_content(js_url, content)
                except Exception as e:
                    logger.debug(f"JS fetch error for {js_url}: {e}")
            
            logger.info(f"JS collection: {len(collected_js)} files, {len(collected_apis)} APIs")
        
        # URL 采集
        if self.config.enable_url_collect and html:
            self._update_progress(ScanStage.COLLECT, phase='url_collect')
            
            url_result = self._url_collector.collect_from_html(html, self.config.target)
            logger.info(f"URL collection: domains={len(url_result.domains)}, static={len(url_result.static_urls)}")
        
        # 浏览器动态采集
        if self.config.enable_browser_collect:
            self._update_progress(ScanStage.COLLECT, phase='browser_collect')
            
            try:
                browser_result = self._browser_collector.collect_all(self.config.target, {
                    'capture_console': True,
                    'capture_storage': True
                })
                
                for js_url in browser_result.get('js_urls', []):
                    if js_url not in [j['url'] for j in collected_js]:
                        try:
                            js_resp = self.session.get(js_url, timeout=self.config.timeout)
                            if js_resp.status_code == 200:
                                collected_js.append({'url': js_url, 'content': js_resp.text})
                        except:
                            pass
                
                for req in browser_result.get('api_requests', []):
                    if req.get('method') in ['POST', 'GET', 'PUT', 'DELETE']:
                        collected_apis.append({
                            'path': req['url'],
                            'method': req['method'],
                            'source': 'browser'
                        })
                
                logger.info(f"Browser collection: {len(browser_result.get('js_urls', []))} JS, {len(browser_result.get('api_requests', []))} API requests")
            except Exception as e:
                logger.warning(f"Browser collection failed: {e}")
        
        # 存储采集结果
        if not hasattr(self.result, 'collector_data'):
            self.result.collector_data = {}
        
        self.result.collector_data['js_files'] = collected_js
        self.result.collector_data['api_paths'] = collected_apis
        self.result.collector_data['js_cache'] = self._js_collector.cache
        
        self._update_progress(
            ScanStage.COLLECT,
            phase='complete',
            total_apis=len(collected_apis)
        )
    
    async def _run_analyzers(self):
        """运行分析阶段"""
        if not self.result or 'api_paths' not in self.result.collector_data:
            return
        
        apis = self.result.collector_data['api_paths']
        api_endpoints: List[APIEndpoint] = []
        alive_apis = []
        high_value_apis = []
        
        self._update_progress(ScanStage.ANALYZE, phase='http_probe')
        
        seen_paths = set()
        for api in apis:
            path = api.get('path', '') or api.get('url', '')
            method = api.get('method', 'GET')
            
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            
            full_url = path if path.startswith('http') else f"{self.config.target.rstrip('/')}{path}"
            
            endpoint = APIEndpoint(
                path=path,
                method=method,
                source=api.get('source', 'unknown'),
                full_url=full_url
            )
            
            score = self._score_endpoint(endpoint)
            endpoint.score = score
            endpoint.is_high_value = score >= self.config.high_value_threshold
            
            api_endpoints.append(endpoint)
            
            if self._probe_endpoint(endpoint):
                alive_apis.append(endpoint)
                if endpoint.is_high_value:
                    high_value_apis.append(endpoint)
        
        self.result.api_endpoints = api_endpoints
        self.result.alive_apis = len(alive_apis)
        self.result.high_value_apis = len(high_value_apis)
        self.result.total_apis = len(api_endpoints)
        
        logger.info(f"Analysis: {len(api_endpoints)} total, {len(alive_apis)} alive, {len(high_value_apis)} high-value")
        
        self._update_progress(
            ScanStage.ANALYZE,
            phase='complete',
            total_apis=len(api_endpoints),
            alive_apis=len(alive_apis),
            high_value_apis=len(high_value_apis)
        )
    
    def _score_endpoint(self, endpoint: APIEndpoint) -> int:
        """
        API 评分算法
        
        评分维度:
        - 路径特征: 包含 admin/user/auth 等关键字 (+3分)
        - HTTP方法: POST/PUT/DELETE (+2分), GET (+1分)
        - 参数数量: 有参数 (+1分)
        - 敏感关键字: 包含 token/key/secret/password (+5分)
        """
        score = 0
        path_lower = endpoint.path.lower()
        
        if any(k in path_lower for k in ['admin', 'user', 'auth', 'login', 'pass', 'token']):
            score += 3
        
        if endpoint.method in ['POST', 'PUT', 'DELETE']:
            score += 2
        elif endpoint.method == 'GET':
            score += 1
        
        if endpoint.parameters:
            score += 1
        
        sensitive_keywords = ['token', 'key', 'secret', 'password', 'jwt', 'bearer', 'auth']
        if any(k in path_lower for k in sensitive_keywords):
            score += 5
        
        return score
    
    def _probe_endpoint(self, endpoint: APIEndpoint) -> bool:
        """探测端点是否存活"""
        try:
            resp = self.session.request(
                endpoint.method,
                endpoint.full_url,
                timeout=self.config.timeout,
                allow_redirects=False
            )
            
            endpoint.status_code = resp.status_code
            endpoint.content_length = len(resp.content)
            
            return resp.status_code < 500
        except Exception as e:
            logger.debug(f"Probe failed for {endpoint.path}: {e}")
            return False
    
    async def _run_testers(self):
        """运行测试阶段"""
        if not self.result or not self.result.api_endpoints:
            return
        
        vulnerabilities: List[Vulnerability] = []
        
        high_value_endpoints = [ep for ep in self.result.api_endpoints if ep.is_high_value]
        test_targets = high_value_endpoints[:50]
        
        self._update_progress(ScanStage.TEST, phase='sqli_test', vulnerabilities=len(vulnerabilities))
        
        if self.config.enable_sqli_test:
            for endpoint in test_targets:
                vulns = await self._test_sqli(endpoint)
                vulnerabilities.extend(vulns)
        
        self._update_progress(ScanStage.TEST, phase='xss_test', vulnerabilities=len(vulnerabilities))
        
        if self.config.enable_xss_test:
            for endpoint in test_targets:
                vulns = await self._test_xss(endpoint)
                vulnerabilities.extend(vulns)
        
        if self.config.enable_idor_test:
            for endpoint in test_targets:
                vulns = await self._test_idor(endpoint)
                vulnerabilities.extend(vulns)
        
        if self.config.enable_info_test:
            for endpoint in test_targets:
                vulns = await self._test_info_disclosure(endpoint)
                vulnerabilities.extend(vulns)
        
        self.result.vulnerabilities = vulnerabilities
        
        self._update_progress(
            ScanStage.TEST,
            phase='complete',
            vulnerabilities=len(vulnerabilities)
        )
        
        logger.info(f"Testing: {len(vulnerabilities)} vulnerabilities found")
    
    async def _test_sqli(self, endpoint: APIEndpoint) -> List[Vulnerability]:
        """SQL 注入测试"""
        vulns = []
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "' AND SLEEP(3)--",
        ]
        
        for payload in sqli_payloads:
            try:
                test_url = f"{endpoint.full_url}?id={payload}" if endpoint.method == 'GET' else endpoint.full_url
                
                resp = self.session.post(
                    test_url,
                    data={'id': payload} if endpoint.method == 'POST' else None,
                    timeout=self.config.timeout
                )
                
                text_lower = resp.text.lower()
                if any(s in text_lower for s in ['sql', 'syntax', 'error', 'mysql', 'oracle', 'warning']):
                    vulns.append(Vulnerability(
                        vuln_type='SQL Injection',
                        severity=Severity.HIGH,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        payload=payload,
                        evidence=f"SQL error detected in response"
                    ))
                    break
            except:
                pass
        
        return vulns
    
    async def _test_xss(self, endpoint: APIEndpoint) -> List[Vulnerability]:
        """XSS 测试"""
        vulns = []
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
        ]
        
        for payload in xss_payloads:
            try:
                test_url = f"{endpoint.full_url}?q={payload}"
                
                resp = self.session.get(test_url, timeout=self.config.timeout)
                
                if payload in resp.text:
                    vulns.append(Vulnerability(
                        vuln_type='XSS',
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        payload=payload,
                        evidence=f"Payload reflected in response"
                    ))
                    break
            except:
                pass
        
        return vulns
    
    async def _test_idor(self, endpoint: APIEndpoint) -> List[Vulnerability]:
        """IDOR 测试"""
        vulns = []
        
        if endpoint.method != 'GET' or 'id' not in endpoint.path.lower():
            return vulns
        
        try:
            resp1 = self.session.get(endpoint.full_url, timeout=self.config.timeout)
            resp2 = self.session.get(f"{endpoint.full_url}?id=99999", timeout=self.config.timeout)
            
            if resp1.status_code == resp2.status_code and len(resp1.content) != len(resp2.content):
                vulns.append(Vulnerability(
                    vuln_type='IDOR',
                    severity=Severity.HIGH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    payload='id=99999',
                    evidence=f"Different response for different ID values"
                ))
        except:
            pass
        
        return vulns
    
    async def _test_info_disclosure(self, endpoint: APIEndpoint) -> List[Vulnerability]:
        """信息泄露测试"""
        vulns = []
        
        sensitive_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email'),
            (r'"password"\s*:\s*"[^"]+"', 'Password in response'),
            (r'"token"\s*:\s*"[^"]+"', 'Token in response'),
            (r'"secret"\s*:\s*"[^"]+"', 'Secret in response'),
        ]
        
        try:
            resp = self.session.get(endpoint.full_url, timeout=self.config.timeout)
            
            for pattern, info_type in sensitive_patterns:
                import re
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                if matches:
                    vulns.append(Vulnerability(
                        vuln_type='Information Disclosure',
                        severity=Severity.LOW,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        payload='',
                        evidence=f"{info_type} found in response"
                    ))
        except:
            pass
        
        return vulns
    
    async def cleanup(self):
        """清理资源"""
        self._running = False
        if self._browser_collector:
            try:
                self._browser_collector.collector.stop()
            except:
                pass


def create_scan_engine(target: str, **kwargs) -> ScanEngine:
    """创建扫描引擎的工厂函数"""
    config = ScanEngineConfig(target=target, **kwargs)
    return ScanEngine(config)
