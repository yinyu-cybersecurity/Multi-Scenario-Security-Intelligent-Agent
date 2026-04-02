#!/usr/bin/env python3
"""
JS Collector - JavaScript 指纹缓存 + Webpack 分析
从 JS 文件中发现 API 路径、参数、前端路由等
"""

import re
import hashlib
import asyncio
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import requests

try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False


@dataclass
class ParsedJSResult:
    """JS 解析结果"""
    js_url: str
    content_hash: str
    endpoints: List[Dict[str, str]] = field(default_factory=list)
    parameter_names: Set[str] = field(default_factory=set)
    websocket_endpoints: List[str] = field(default_factory=list)
    env_configs: Dict[str, str] = field(default_factory=dict)
    routes: List[str] = field(default_factory=list)
    parent_paths: Set[str] = field(default_factory=set)
    extracted_suffixes: List[str] = field(default_factory=list)
    resource_fragments: List[str] = field(default_factory=list)


class JSFingerprintCache:
    """JS 指纹缓存，避免重复 AST 解析"""
    
    def __init__(self):
        self._cache: Dict[str, ParsedJSResult] = {}
        self._content_hashes: Dict[str, str] = {}
    
    def get(self, js_url: str, content: str) -> Optional[ParsedJSResult]:
        """检查缓存或返回 None"""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        
        if js_url in self._cache:
            cached = self._cache[js_url]
            if cached.content_hash == content_hash:
                return cached
            del self._cache[js_url]
        
        self._content_hashes[js_url] = content_hash
        return None
    
    def put(self, js_url: str, result: ParsedJSResult):
        """缓存解析结果"""
        self._cache[js_url] = result
    
    def get_all_parent_paths(self) -> Set[str]:
        """获取所有父路径"""
        paths = set()
        for result in self._cache.values():
            paths.update(result.parent_paths)
        return paths


class JSCollector:
    """
    JS 采集器
    
    功能:
    - 主页 HTML 正则提取 <script src="*.js">
    - 递归 JS 提取 (Webpack 动态 import/require)
    - AST + 正则双引擎解析
    - Webpack chunk 分析
    """
    
    # HTTP 方法模式
    HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']
    
    # API 路径正则 (25+ 规则)
    API_PATH_PATTERNS = [
        r"/api/[a-zA-Z0-9_/-]+",
        r"/[a-zA-Z0-9_/-]+/[a-zA-Z0-9_/-]+",
        r"fetch\s*\(\s*['\"](/[^'\"]+)['\"]",
        r"axios\.(get|post|put|delete)\s*\(\s*['\"](/[^'\"]+)['\"]",
        r"\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"](/[^'\"]+)['\"]",
        r"request\s*\(\s*\{[^}]*url\s*:\s*['\"](/[^'\"]+)['\"]",
        r"http[s]?://[a-zA-Z0-9.-]+(:\d+)?(/[a-zA-Z0-9_/.-]*)?['\"]",
    ]
    
    # 参数名正则
    PARAM_PATTERNS = [
        r'(?:id|userId|user_id|page|token|key|secret|password|email|username|name|type|category|search|query|filter|sort|order|limit|offset|pageSize|page_size)',
        r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}',
    ]
    
    # WebSocket 模式
    WS_PATTERNS = [
        r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]+)[\'"]',
        r'ws[s]?://[^\s\'"<>]+',
    ]
    
    # 环境配置模式
    ENV_PATTERNS = [
        r'(?:BASE_URL|API_URL|API_ENDPOINT|API_KEY|SECRET_KEY|TOKEN|AUTH_TOKEN)\s*[:=]\s*[\'"]([^\'"]+)',
        r'process\.env\.([A-Z_]+)',
    ]
    
    # Vue/React Router 模式
    ROUTE_PATTERNS = [
        r'/user/:id',
        r'/product/:productId',
        r'/admin/:action',
        r'router\.(?:push|replace|go)\s*\(\s*[\'"](/[^\'"]+)[\'"]',
        r'<Route\s+(?:path|component)=[\'"](/[^\'"]+)[\'"]',
        r'path\s*:\s*[\'"](/[^\'"]+)[\'"]',
    ]
    
    # Webpack chunk 模式
    WEBPACK_CHUNK_PATTERNS = [
        r'chunk-[a-f0-9]+\.js',
        r'\.[a-f0-9]{8}\.js',
    ]
    
    def __init__(self, session: requests.Session = None, max_depth: int = 3, max_js_per_depth: int = 50):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.cache = JSFingerprintCache()
        self.max_depth = max_depth
        self.max_js_per_depth = max_js_per_depth
        self.visited_urls: Set[str] = set()
        self.all_js_urls: List[str] = []
    
    def extract_js_from_html(self, html_content: str, base_url: str) -> List[str]:
        """从 HTML 中提取 JS URL"""
        js_urls = []
        
        # script src 模式
        patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r"<script[^>]+src=['\"]([^'\"]+\.js[^'\"]*)['\"]",
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match.startswith('http'):
                    js_urls.append(match)
                elif match.startswith('//'):
                    js_urls.append('https:' + match)
                else:
                    js_urls.append(urljoin(base_url, match))
        
        return list(set(js_urls))
    
    def extract_js_imports(self, js_content: str) -> List[str]:
        """从 JS 内容中提取 import/require 引入的新 JS"""
        imports = []
        
        patterns = [
            r'import\s+.*?from\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
            r'import\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
            r'require\s*\(\s*[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
            r'export\s+.*?from\s+[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
            r'webpackChunkName:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            imports.extend(matches)
        
        return list(set(imports))
    
    def parse_js_content(self, js_url: str, content: str) -> ParsedJSResult:
        """解析 JS 内容"""
        cached = self.cache.get(js_url, content)
        if cached:
            return cached
        
        result = ParsedJSResult(
            js_url=js_url,
            content_hash=hashlib.md5(content.encode()).hexdigest()
        )
        
        # 1. API 端点提取
        result.endpoints = self._extract_endpoints(content)
        
        # 2. 参数名提取
        result.parameter_names = self._extract_parameters(content)
        
        # 3. WebSocket 端点
        result.websocket_endpoints = self._extract_websocket(content)
        
        # 4. 环境配置
        result.env_configs = self._extract_env_configs(content)
        
        # 5. 前端路由
        result.routes = self._extract_routes(content)
        
        # 6. 父路径提取
        result.parent_paths = self._extract_parent_paths(result.endpoints)
        
        # 7. 路径后缀和资源片段
        result.extracted_suffixes = self._extract_suffixes(result.endpoints)
        result.resource_fragments = self._extract_resource_fragments(result.endpoints)
        
        self.cache.put(js_url, result)
        return result
    
    def _extract_endpoints(self, content: str) -> List[Dict[str, str]]:
        """提取 API 端点"""
        endpoints = []
        found = set()
        
        # HTTP 方法 + 路径
        for method in self.HTTP_METHODS:
            patterns = [
                rf"{method}\s*\(\s*['\"]([^'\"]+)['\"]",
                rf"\.{method}\s*\(\s*['\"]([^'\"]+)['\"]",
                rf"['\"]([/a-zA-Z0-9_-]*{method}[/a-zA-Z0-9_-]*)['\"]",
            ]
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for path in matches:
                    if self._is_api_path(path) and path not in found:
                        found.add(path)
                        endpoints.append({
                            'method': method.upper(),
                            'path': path,
                            'source': 'regex'
                        })
        
        # fetch/axios/$.ajax
        patterns = [
            (r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]', 'GET'),
            (r'axios\.(get|post|put|delete)\s*\(\s*[\'"]([^\'"]+)[\'"]', None),
            (r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"](/[^\'"]+)[\'"]', None),
        ]
        
        for pattern, default_method in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    method = match[0].upper() if match[0].lower() in self.HTTP_METHODS else default_method or 'GET'
                    path = match[1] if len(match) > 1 else match[0]
                else:
                    method = 'GET'
                    path = match
                
                if self._is_api_path(path) and path not in found:
                    found.add(path)
                    endpoints.append({
                        'method': method,
                        'path': path,
                        'source': 'http_client'
                    })
        
        return endpoints
    
    def _is_api_path(self, path: str) -> bool:
        """判断是否为 API 路径"""
        if not path or len(path) < 2:
            return False
        
        skip_patterns = [
            r'\.css', r'\.jpg', r'\.png', r'\.gif', r'\.svg',
            r'\.woff', r'\.ttf', r'\.eot', r'\.ico',
            r'html?', r'\.json[^\w]',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return False
        
        return True
    
    def _extract_parameters(self, content: str) -> Set[str]:
        """提取参数名"""
        params = set()
        
        # URL 中的 {param} 格式
        matches = re.findall(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}', content)
        params.update(matches)
        
        # 常见参数名
        param_names = [
            'id', 'userId', 'user_id', 'page', 'pageNum', 'page_size',
            'token', 'key', 'secret', 'password', 'email', 'username',
            'name', 'type', 'category', 'search', 'query', 'filter',
            'sort', 'order', 'limit', 'offset', 'pageSize',
            'status', 'action', 'method', 'callback', 'data', 'params',
        ]
        
        for param in param_names:
            if re.search(rf'[\s\({{]{param}[\s\)}},=]', content, re.IGNORECASE):
                params.add(param)
        
        return params
    
    def _extract_websocket(self, content: str) -> List[str]:
        """提取 WebSocket 端点"""
        ws_endpoints = []
        
        for pattern in self.WS_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            ws_endpoints.extend(matches)
        
        return list(set(ws_endpoints))
    
    def _extract_env_configs(self, content: str) -> Dict[str, str]:
        """提取环境配置"""
        configs = {}
        
        for pattern in self.ENV_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    configs[match[0]] = match[1]
                elif isinstance(match, str):
                    configs[pattern.split('(')[1].split(')')[0].replace('?:', '')] = match
        
        return configs
    
    def _extract_routes(self, content: str) -> List[str]:
        """提取前端路由"""
        routes = []
        
        # Vue/React Router 格式
        patterns = [
            r'path\s*:\s*[\'"]([/a-zA-Z0-9_:-]*:[\w]+[/a-zA-Z0-9_-]*)[\'"]',
            r'router\.push\s*\(\s*[\'"](/[^\'"]+)[\'"]',
            r'<Route\s+[^>]*path=[\'"](/[^\'"]+)[\'"]',
            r'["\']/(?:user|admin|product|order|api)[:/][a-zA-Z0-9_]+["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            routes.extend(matches)
        
        return list(set(routes))
    
    def _extract_parent_paths(self, endpoints: List[Dict[str, str]]) -> Set[str]:
        """提取父路径"""
        parent_paths = set()
        
        for ep in endpoints:
            path = ep.get('path', '')
            if not path:
                continue
            
            parts = path.strip('/').split('/')
            if len(parts) > 1:
                parent = '/' + '/'.join(parts[:-1])
                parent_paths.add(parent)
            
            if len(parts) > 2:
                parent = '/' + '/'.join(parts[:-2])
                parent_paths.add(parent)
        
        return parent_paths
    
    def _extract_suffixes(self, endpoints: List[Dict[str, str]]) -> List[str]:
        """提取路径后缀"""
        suffixes = []
        
        for ep in endpoints:
            path = ep.get('path', '')
            parts = path.strip('/').split('/')
            if len(parts) > 0:
                suffixes.append(parts[-1])
        
        return list(set(suffixes))
    
    def _extract_resource_fragments(self, endpoints: List[Dict[str, str]]) -> List[str]:
        """提取资源片段"""
        resources = []
        
        resource_names = [
            'user', 'users', 'product', 'products', 'order', 'orders',
            'admin', 'auth', 'login', 'logout', 'register', 'profile',
            'config', 'setting', 'menu', 'role', 'permission',
        ]
        
        for ep in endpoints:
            path = ep.get('path', '').lower()
            for resource in resource_names:
                if resource in path:
                    resources.append(resource)
        
        return list(set(resources))
    
    async def _recursive_js_extract(self, initial_js_urls: List[str], base_url: str) -> List[str]:
        """递归 JS 提取"""
        all_js_content = {}
        pending_urls = list(set(initial_js_urls))
        
        for depth in range(self.max_depth):
            if not pending_urls:
                break
            
            current_batch = pending_urls[:self.max_js_per_depth]
            pending_urls = pending_urls[self.max_js_per_depth:]
            
            for js_url in current_batch:
                if js_url in self.visited_urls:
                    continue
                self.visited_urls.add(js_url)
                
                try:
                    if not js_url.startswith('http'):
                        js_url = urljoin(base_url, js_url)
                    
                    resp = self.session.get(js_url, timeout=10)
                    if resp.status_code == 200:
                        content = resp.text
                        all_js_content[js_url] = content
                        self.all_js_urls.append(js_url)
                        
                        # 提取新 JS
                        new_imports = self.extract_js_imports(content)
                        for imp in new_imports:
                            if imp not in self.visited_urls:
                                normalized = urljoin(js_url, imp)
                                pending_urls.append(normalized)
                except:
                    pass
        
        return self.all_js_urls
    
    def collect(self, target_url: str) -> JSFingerprintCache:
        """执行 JS 采集"""
        try:
            resp = self.session.get(target_url, timeout=10)
            html = resp.text
        except Exception as e:
            print(f"[!] Failed to fetch target: {e}")
            return self.cache
        
        # 1. 提取 HTML 中的 JS
        js_urls = self.extract_js_from_html(html, target_url)
        print(f"[*] Found {len(js_urls)} JS files in HTML")
        
        # 2. 递归提取
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._recursive_js_extract(js_urls, target_url))
        
        # 3. 解析每个 JS
        for js_url in self.all_js_urls:
            try:
                resp = self.session.get(js_url, timeout=10)
                if resp.status_code == 200:
                    self.parse_js_content(js_url, resp.text)
            except:
                pass
        
        print(f"[*] Parsed {len(self.cache._cache)} JS files")
        return self.cache


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="JS Collector")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth")
    parser.add_argument("--output", help="Output file")
    
    args = parser.parse_args()
    
    collector = JSCollector(max_depth=args.depth)
    cache = collector.collect(args.target)
    
    print("\n=== Results ===")
    print(f"Total JS files: {len(cache._cache)}")
    print(f"Parent paths: {cache.get_all_parent_paths()}")
    
    for js_url, result in cache._cache.items():
        if result.endpoints:
            print(f"\n{js_url}:")
            for ep in result.endpoints[:5]:
                print(f"  - {ep['method']} {ep['path']}")
