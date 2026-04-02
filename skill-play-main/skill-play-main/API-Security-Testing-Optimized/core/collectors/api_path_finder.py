#!/usr/bin/env python3
"""
API Path Finder - API 路径发现器
使用 25+ 正则规则从 JS/HTML/API 响应中提取 API 路径
"""

import re
from typing import List, Dict, Set, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field


@dataclass
class APIFindResult:
    """API 发现结果"""
    path: str
    method: str = "GET"
    source_type: str = ""
    url_type: str = ""
    parameters: Set[str] = field(default_factory=set)
    full_url: str = ""


class ApiPathFinder:
    """
    API 路径发现器
    
    功能:
    - 25+ 正则规则发现 API 路径
    - 智能路径组合
    - 父路径探测
    - 跨来源 Fuzzing
    """
    
    # 常见 RESTful 后缀
    RESTFUL_SUFFIXES = [
        'list', 'get', 'add', 'create', 'update', 'edit', 'delete', 'remove',
        'detail', 'info', 'view', 'show', 'query', 'search', 'fetch', 'load',
        'save', 'submit', 'submit', 'export', 'import', 'upload', 'download',
        'config', 'setting', 'settings', 'options', 'permissions', 'all',
    ]
    
    # 常见参数名
    COMMON_PARAMS = [
        'id', 'page', 'pageNum', 'pageSize', 'page_size', 'num', 'size',
        'limit', 'offset', 'start', 'end', 'from', 'to', 'date', 'time',
        'type', 'category', 'status', 'state', 'flag', 'mode', 'action',
        'name', 'title', 'desc', 'description', 'content', 'text', 'data',
        'token', 'key', 'secret', 'email', 'phone', 'mobile', 'username',
        'userId', 'user_id', 'userid', 'role', 'permission', 'menu',
        'search', 'query', 'keyword', 'filter', 'sort', 'order', 'by',
    ]
    
    # API 路径正则 (25+ 规则)
    API_PATTERNS = [
        # fetch
        (r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", "GET"),
        (r"fetch\s*\(\s*[`'\"]([^`'\"]+)[`'\"]", "GET"),
        
        # axios
        (r"axios\.(get|post|put|delete|patch|head)\s*\(\s*['\"]([^'\"]+)['\"]", None),
        (r"axios\.(get|post|put|delete|patch|head)\s*\(\s*[`'\"]([`'\"]+)[`'\"]", None),
        
        # $.ajax
        (r"\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"](/[^'\"]+)['\"]", "GET"),
        (r"\$\.ajax\s*\(\s*\{[^}]*type\s*:\s*['\"]([^'\"]+)['\"]", None),
        
        # request
        (r"request\s*\(\s*\{[^}]*url\s*:\s*['\"](/[^'\"]+)['\"]", None),
        (r"request\s*\(\s*['\"]([^'\"]+)['\"]", "GET"),
        
        # 直接路径匹配
        (r"['\"](/api/[a-zA-Z0-9_/-]+)['\"]", "GET"),
        (r"['\"](\/v\d+/[a-zA-Z0-9_/-]+)['\"]", "GET"),
        (r"['\"](\/[a-zA-Z]+/[a-zA-Z0-9_/-]+)['\"]", "GET"),
        
        # RESTful 模板
        (r"['\"](/[a-zA-Z]+/\{[a-zA-Z_][a-zA-Z0-9_]*\})['\"]", "GET"),
        (r"['\"](/[a-zA-Z]+/[a-zA-Z]+/\{[a-zA-Z_][a-zA-Z0-9_]*\})['\"]", "GET"),
        
        # WebSocket
        (r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]", "WS"),
        (r"wss?://[^\s'\"<>]+", "WS"),
        
        # GraphQL
        (r"graphql\s*\(\s*\{[^}]*query\s*:\s*['\"]([^'\"]+)['\"]", "POST"),
        (r"gql\s*`[^`]+query\s+(\w+)", "POST"),
        
        # 相对路径
        (r"\.\s*\+\s*['\"](/[^'\"]+)['\"]", "GET"),
        (r"baseURL\s*\+\s*['\"](/[^'\"]+)['\"]", "GET"),
        
        # JSON 数据中的路径
        (r"\"url\"\s*:\s*\"(/[^\"]+)\"", "GET"),
        (r"\"path\"\s*:\s*\"(/[^\"]+)\"", "GET"),
        (r"\"endpoint\"\s*:\s*\"(/[^\"]+)\"", "GET"),
        (r"\"uri\"\s*:\s*\"(/[^\"]+)\"", "GET"),
        
        # 完整 URL
        (r"https?://[a-zA-Z0-9.-]+(:\d+)?(/[a-zA-Z0-9_/.-]*)?['\"]", "GET"),
        
        # Vue Router
        (r"path\s*:\s*['\"](/[^'\"]+)['\"]", "GET"),
        (r"router\.push\s*\(\s*['\"](/[^'\"]+)['\"]", "GET"),
        (r"router\.replace\s*\(\s*['\"](/[^'\"]+)['\"]", "GET"),
        
        # React Router
        (r"<Route\s+[^>]*path=['\"](/[^'\"]+)['\"]", "GET"),
        (r"Link\s+[^>]*to=['\"](/[^'\"]+)['\"]", "GET"),
        
        # 路径参数
        (r":([a-zA-Z_][a-zA-Z0-9_]*)\s*[,})]", ""),
    ]
    
    def __init__(self):
        self.found_paths: Set[str] = set()
        self.found_apis: List[APIFindResult] = []
    
    def find_api_paths_in_text(self, text: str, source: str = "text") -> List[APIFindResult]:
        """从文本中发现 API 路径"""
        results = []
        
        for pattern, default_method in self.API_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    if len(match) == 2:
                        method = match[0].upper() if match[0].lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'] else default_method or "GET"
                        path = match[1]
                    else:
                        method = default_method or "GET"
                        path = match[0]
                else:
                    method = default_method or "GET"
                    path = match
                
                if self._is_valid_path(path):
                    full_path = self._normalize_path(path)
                    if full_path and full_path not in self.found_paths:
                        self.found_paths.add(full_path)
                        
                        api_result = APIFindResult(
                            path=full_path,
                            method=method,
                            source_type=source,
                            url_type="discovered"
                        )
                        results.append(api_result)
                        self.found_apis.append(api_result)
        
        return results
    
    def _is_valid_path(self, path: str) -> bool:
        """验证路径是否有效"""
        if not path or len(path) < 2:
            return False
        
        if path.startswith('//') or path.startswith('http'):
            return False
        
        skip_patterns = [
            r'\.css', r'\.jpg', r'\.png', r'\.gif', r'\.svg', r'\.ico',
            r'\.woff', r'\.ttf', r'\.eot', r'\.map$', r'\.js$',
            r'github\.com', r'cdn\.', r'googleapis\.com',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return False
        
        return True
    
    def _normalize_path(self, path: str) -> str:
        """规范化路径"""
        path = path.strip()
        
        if not path.startswith('/') and not path.startswith('http'):
            path = '/' + path
        
        path = re.sub(r'["\']\s*\+\s*["\']', '', path)
        
        path = re.sub(r'\{[^}]+\}', '{param}', path)
        
        return path
    
    def get_all_paths(self) -> List[str]:
        """获取所有发现的路径"""
        return list(self.found_paths)
    
    def get_parent_paths(self) -> Set[str]:
        """获取所有父路径"""
        parent_paths = set()
        
        for path in self.found_paths:
            parts = path.strip('/').split('/')
            if len(parts) > 1:
                for i in range(1, len(parts)):
                    parent = '/' + '/'.join(parts[:i])
                    parent_paths.add(parent)
        
        return parent_paths
    
    def get_resource_names(self) -> Set[str]:
        """获取所有资源名"""
        resources = set()
        
        for path in self.found_paths:
            parts = path.strip('/').split('/')
            for part in parts:
                if part not in ['api', 'v1', 'v2', 'v3', 'rest']:
                    if not part.startswith('{') and not part.startswith(':'):
                        if len(part) > 1 and not part.isdigit():
                            resources.add(part)
        
        return resources
    
    def combine_paths(self, base_paths: Set[str], suffixes: List[str]) -> List[str]:
        """组合路径: 父路径 + 后缀"""
        combined = []
        
        for base in base_paths:
            for suffix in suffixes[:20]:
                path = f"{base}/{suffix}"
                if path not in self.found_paths:
                    combined.append(path)
        
        return combined
    
    def generate_fuzz_targets(self, parent_paths: Set[str], resources: Set[str]) -> List[str]:
        """生成 Fuzz 目标"""
        targets = []
        
        for parent in parent_paths:
            targets.append(parent)
            
            for suffix in self.RESTFUL_SUFFIXES[:15]:
                path = f"{parent}/{suffix}"
                if path not in self.found_paths:
                    targets.append(path)
            
            for resource in list(resources)[:10]:
                path = f"{parent}/{resource}"
                if path not in self.found_paths:
                    targets.append(path)
                
                for suffix in self.RESTFUL_SUFFIXES[:10]:
                    path = f"{parent}/{resource}/{suffix}"
                    if path not in self.found_paths:
                        targets.append(path)
        
        return targets[:200]


class ApiPathCombiner:
    """API 路径组合器 - 跨来源智能路径组合"""
    
    def __init__(self):
        self.path_segments: Set[str] = set()
        self.base_urls: Set[str] = set()
    
    def add_path_segment(self, segment: str):
        """添加路径片段"""
        if segment and len(segment) > 1:
            self.path_segments.add(segment)
    
    def add_base_url(self, url: str):
        """添加 Base URL"""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        self.base_urls.add(base)
        
        path = parsed.path
        if path:
            parts = path.strip('/').split('/')
            for part in parts:
                if part:
                    self.path_segments.add(part)
    
    def combine_cross_source(self, html_paths: List[str], js_paths: List[str], api_paths: List[str]) -> List[str]:
        """跨来源组合路径"""
        all_segments: Set[str] = set()
        
        for path in html_paths + js_paths + api_paths:
            parts = path.strip('/').split('/')
            for part in parts:
                if part and not part.startswith('{') and not part.isdigit():
                    all_segments.add(part)
        
        combined = []
        
        common_prefixes = ['/api', '/v1', '/v2', '/admin', '/user', '/auth', '/service']
        
        for prefix in common_prefixes:
            for segment in list(all_segments)[:30]:
                if segment not in common_prefixes:
                    path = f"{prefix}/{segment}"
                    if path not in combined:
                        combined.append(path)
        
        return combined[:100]
