#!/usr/bin/env python3
"""
URL Collector - 域名/URL 采集器
从 HTML、JS、响应中发现域名、URL、Base URL
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field
import requests


@dataclass
class URLCollectionResult:
    """URL 采集结果"""
    domains: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    base_urls: Set[str] = field(default_factory=set)
    static_urls: Set[str] = field(default_factory=set)
    api_urls: Set[str] = field(default_factory=set)
    inline_urls: Set[str] = field(default_factory=set)
    redirected_urls: Set[str] = field(default_factory=set)


class URLCollector:
    """
    URL 采集器
    
    功能:
    - 域名/子域名采集
    - Base URL 发现 (微服务名称提取)
    - 静态地址采集
    - 跨域 URL 采集
    - API URL 采集
    - 内联 URL 提取
    """
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.result = URLCollectionResult()
    
    def collect_from_html(self, html_content: str, base_url: str) -> URLCollectionResult:
        """从 HTML 中采集 URL"""
        
        # 1. 提取所有链接
        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r"href=['\"]([^'\"]+)['\"]",
            r'src=["\']([^"\']+)["\']',
            r"src=['\"]([^'\"]+)['\"]",
            r'url\(["\']?([^"\'()]+)["\']?\)',
            r'url\(["\']?([^"\'()]+)["\']?\)',
        ]
        
        for pattern in link_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for url in matches:
                self._process_url(url, base_url)
        
        # 2. 提取 meta 标签中的 URL
        meta_patterns = [
            r'<meta[^>]+content=["\']([^"\']+)["\']',
            r'<link[^>]+href=["\']([^"\']+)["\']',
        ]
        
        for pattern in meta_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for content in matches:
                urls = re.findall(r'https?://[^\s"\'<>]+', content)
                for url in urls:
                    self._process_url(url, base_url)
        
        # 3. 提取 JSON/JS 中的 URL
        json_patterns = [
            r'["\']((https?|wss?)://[^\s"\'<>]+)["\']',
            r'["\'](/[a-zA-Z0-9_/-]+\.json)["\']',
            r'api[Uu]rl\s*[:=]\s*["\']([^"\']+)["\']',
            r'base[Uu]rl\s*[:=]\s*["\']([^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for url in matches:
                self._process_url(url, base_url)
        
        return self.result
    
    def collect_from_js(self, js_content: str, base_url: str) -> URLCollectionResult:
        """从 JS 中采集 URL"""
        
        # 1. 提取字符串中的 URL
        url_patterns = [
            r'["\']((https?|wss?)://[^\s"\'<>]+)["\']',
            r'["\'](/[a-zA-Z0-9_/.-]+)["\']',
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for url in matches:
                self._process_url(url, base_url)
        
        # 2. 提取配置对象
        config_patterns = [
            r'(?:baseURL|apiURL|apiUrl|endpoint|BaseUrl)\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:BASE_URL|API_URL|API_ENDPOINT)\s*[:=]\s*["\']([^"\']+)["\']',
            r'process\.env\.([A-Z_]+)\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    url = match[-1]
                else:
                    url = match
                self._process_url(url, base_url)
        
        # 3. 提取 WebSocket URL
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'wss?://[^\s"\'<>]+',
        ]
        
        for pattern in ws_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for url in matches:
                self._process_url(url, base_url)
        
        return self.result
    
    def collect_from_response(self, response_text: str, base_url: str, content_type: str = "") -> URLCollectionResult:
        """从 API 响应中采集 URL"""
        
        if 'json' in content_type.lower() or response_text.strip().startswith('{'):
            try:
                import json
                data = json.loads(response_text)
                text = json.dumps(data)
            except:
                text = response_text
        else:
            text = response_text
        
        return self.collect_from_html(text, base_url)
    
    def _process_url(self, url: str, base_url: str):
        """处理单个 URL"""
        if not url:
            return
        
        url = url.strip()
        
        if url.startswith('//'):
            url = 'https:' + url
        
        if url.startswith('/'):
            url = urljoin(base_url, url)
        
        parsed = urlparse(url)
        
        if not parsed.scheme or not parsed.netloc:
            if '/' in url:
                url = urljoin(base_url, url)
                parsed = urlparse(url)
        
        if not parsed.scheme or not parsed.netloc:
            return
        
        domain = parsed.netloc.lower()
        
        if self._is_ip(domain):
            self.result.domains.add(domain)
        else:
            self.result.subdomains.add(domain)
            
            parts = domain.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
                self.result.domains.add(base_domain)
        
        path = parsed.path
        if path:
            if '/api/' in path or '/v' in path:
                self.result.api_urls.add(url)
            elif self._is_static_resource(path):
                self.result.static_urls.add(url)
            else:
                self.result.inline_urls.add(url)
        
        if '/api/' in path:
            base = parsed.scheme + '://' + parsed.netloc
            api_path = path.split('/api/')[0] + '/api' if '/api/' in path else path
            self.result.base_urls.add(api_path)
    
    def _is_ip(self, host: str) -> bool:
        """判断是否为 IP 地址"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, host))
    
    def _is_static_resource(self, path: str) -> bool:
        """判断是否为静态资源"""
        static_extensions = [
            '.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.otf', '.map',
            '.html', '.htm', '.xml', '.json',
        ]
        
        for ext in static_extensions:
            if path.lower().endswith(ext):
                return True
        
        return False
    
    def discover_base_urls(self, urls: Set[str]) -> Set[str]:
        """发现 Base URL (微服务名称)"""
        base_urls = set()
        
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path
            
            if '/api/' in path:
                parts = path.split('/')
                if len(parts) >= 3:
                    idx = parts.index('api')
                    if idx >= 1:
                        base = '/' + '/'.join(parts[:idx+1])
                        base_urls.add(base)
            
            elif '/v' in path:
                match = re.search(r'(/v\d+)', path)
                if match:
                    base_urls.add(match.group(1))
        
        return base_urls
    
    def get_all_collectors_results(self) -> Dict[str, Set[str]]:
        """获取所有采集结果"""
        return {
            'domains': self.result.domains,
            'subdomains': self.result.subdomains,
            'base_urls': self.result.base_urls,
            'static_urls': self.result.static_urls,
            'api_urls': self.result.api_urls,
            'inline_urls': self.result.inline_urls,
        }


class DomainURLCollector:
    """域名/URL 专项采集器"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityBot/1.0)'
        })
    
    def collect_from_cname(self, domain: str) -> Set[str]:
        """通过 CNAME 记录发现子域名"""
        subdomains = set()
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            answers = resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                if domain in cname:
                    subdomains.add(cname)
        except:
            pass
        
        return subdomains
    
    def collect_from_certificate(self, domain: str) -> Set[str]:
        """通过 SSL 证书发现子域名"""
        subdomains = set()
        
        try:
            import socket
            import ssl
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if 'subjectAltName' in cert:
                        for san in cert['subjectAltName']:
                            if san[0] == 'DNS':
                                subdomains.add(san[1].lower())
        except:
            pass
        
        return subdomains
    
    def collect_from_wayback(self, domain: str) -> Set[str]:
        """通过 Wayback Machine 发现历史 URL"""
        urls = set()
        
        try:
            resp = self.session.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=100",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    for row in data[1:]:
                        if len(row) >= 2:
                            urls.add(row[2])
        except:
            pass
        
        return urls
