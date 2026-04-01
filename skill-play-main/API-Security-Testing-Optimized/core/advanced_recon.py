#!/usr/bin/env python3
"""
Advanced Recon - 高级侦察模块
超越 JS 采集的多源信息收集

参考渗透测试工程师的侦察方法：
1. Swagger/OpenAPI 发现
2. WebSocket 探测
3. DNS/子域名枚举
4. 错误信息分析
5. 技术栈指纹
6. 响应差异分析
"""

import re
import socket
import time
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
import requests

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


@dataclass
class ReconResult:
    """侦察结果"""
    swagger_endpoints: List[str] = field(default_factory=list)
    websocket_urls: List[str] = field(default_factory=list)
    subdomains: Set[str] = field(default_factory=set)
    tech_stack: Dict[str, str] = field(default_factory=dict)
    api_patterns: Set[str] = field(default_factory=set)
    interesting_urls: List[str] = field(default_factory=list)
    error_leaks: List[Dict] = field(default_factory=list)
    fingerprint: Dict[str, Any] = field(default_factory=dict)


class SwaggerDiscoverer:
    """Swagger/OpenAPI 文档发现
    
    优化：基于 API 父路径探测，比根路径探测更高效
    """
    
    COMMON_SWAGGER_PATHS = [
        '/swagger-ui.html',
        '/swagger-ui/index.html',
        '/swagger-ui/',
        '/api-docs',
        '/api-docs/',
        '/v3/api-docs',
        '/v3/api-docs/',
        '/v3/api-docs.yaml',
        '/v2/api-docs',
        '/v2/api-docs.yaml',
        '/swagger.json',
        '/swagger/v1/swagger.json',
        '/swagger/v2/swagger.json',
        '/openapi.json',
        '/openapi.yaml',
        '/openapi/3.0.yaml',
        '/api/openapi.json',
        '/api/swagger.json',
        '/doc.json',
        '/api-doc',
        '/swagger-doc',
        '/api.html',
        '/dev/api-doc',
        '/qa/api-doc',
        '/test/api-doc',
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.discovered: List[Dict] = []
    
    def discover(self, base_url: str, api_parent_paths: List[str] = None) -> List[Dict]:
        """发现 Swagger 文档
        
        Args:
            base_url: 目标基础 URL
            api_parent_paths: 已发现的 API 父路径列表 (用于精确探测)
        """
        results = []
        checked_urls = set()
        
        # 1. 首先在 API 父路径后探测 (更高效)
        if api_parent_paths:
            for parent in api_parent_paths[:15]:
                for swagger_path in self.COMMON_SWAGGER_PATHS:
                    url = base_url.rstrip('/') + parent + swagger_path
                    if url in checked_urls:
                        continue
                    checked_urls.add(url)
                    
                    result = self._check_swagger_url(url)
                    if result:
                        results.append(result)
        
        # 2. 然后在根路径探测
        for swagger_path in self.COMMON_SWAGGER_PATHS:
            url = base_url.rstrip('/') + swagger_path
            if url in checked_urls:
                continue
            checked_urls.add(url)
            
            result = self._check_swagger_url(url)
            if result:
                results.append(result)
        
        self.discovered = results
        return results
    
    def _check_swagger_url(self, url: str) -> Optional[Dict]:
        """检查单个 URL 是否为 Swagger 文档"""
        try:
            resp = self.session.get(url, timeout=5, allow_redirects=True)
            
            if resp.status_code == 200:
                content_type = resp.headers.get('Content-Type', '')
                
                if 'json' in content_type or url.endswith(('.json', '.yaml', '.yml')):
                    return {
                        'url': url,
                        'type': 'openapi',
                        'status': 200,
                        'is_json': True
                    }
                elif 'html' in content_type and 'swagger' in resp.text.lower():
                    return {
                        'url': url,
                        'type': 'swagger-ui',
                        'status': 200,
                        'is_json': False
                    }
                elif 'html' in content_type:
                    return {
                        'url': url,
                        'type': 'spa-fallback',
                        'status': 200,
                        'is_json': False
                    }
                    
            elif resp.status_code in [401, 403]:
                if 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower():
                    return {
                        'url': url,
                        'type': 'swagger-protected',
                        'status': resp.status_code
                    }
                    
        except Exception:
            pass
        
        return None
        
        for path in self.COMMON_SWAGGER_PATHS:
            url = base_url.rstrip('/') + path
            
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=True)
                
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    
                    if 'json' in content_type or path.endswith(('.json', '.yaml', '.yml')):
                        results.append({
                            'url': url,
                            'type': 'openapi',
                            'status': 200
                        })
                    elif 'html' in content_type and 'swagger' in resp.text.lower():
                        results.append({
                            'url': url,
                            'type': 'swagger-ui',
                            'status': 200
                        })
                
                elif resp.status_code == 401 or resp.status_code == 403:
                    if 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower():
                        results.append({
                            'url': url,
                            'type': 'swagger-protected',
                            'status': resp.status_code
                        })
                        
            except Exception:
                pass
        
        self.discovered = results
        return results
    
    def parse_swagger(self, url: str) -> Optional[Dict]:
        """解析 Swagger/OpenAPI 文档"""
        try:
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                content = resp.text
                
                if content.strip().startswith('{'):
                    import json
                    spec = json.loads(content)
                else:
                    return None
                
                info = spec.get('info', {})
                paths = spec.get('paths', {})
                
                endpoints = []
                for path, methods in paths.items():
                    for method, details in methods.items():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                            endpoints.append({
                                'path': path,
                                'method': method.upper(),
                                'summary': details.get('summary', ''),
                                'parameters': details.get('parameters', []),
                            })
                
                return {
                    'title': info.get('title', ''),
                    'version': info.get('version', ''),
                    'endpoints': endpoints,
                    'total': len(endpoints)
                }
                
        except Exception:
            pass
        
        return None


class WebSocketDiscoverer:
    """WebSocket 发现"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session
    
    def discover_from_js(self, js_content: str, base_url: str) -> List[str]:
        """从 JS 中发现 WebSocket URL"""
        ws_urls = []
        
        patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'wss?://[^\s"\'<>]+',
            r'["\'](\/ws[s]?[^"\']+)["\']',
            r'websocket\s*:\s*["\']([^"\']+)["\']',
            r'SocketIO\s*\(\s*["\']([^"\']+)["\']',
            r'socket\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str) and match:
                    ws_urls.append(match)
        
        return list(set(ws_urls))
    
    def discover_from_headers(self, base_url: str) -> List[str]:
        """从 HTTP 头发现 WebSocket"""
        ws_hints = []
        
        try:
            resp = self.session.get(base_url, timeout=5)
            
            upgrade = resp.headers.get('Upgrade', '')
            if upgrade and 'websocket' in upgrade.lower():
                ws_hints.append('websocket-supported')
            
            sec_websocket = resp.headers.get('Sec-WebSocket-Extensions', '')
            if sec_websocket:
                ws_hints.append(sec_websocket)
                
        except:
            pass
        
        return ws_hints


class TechFingerprinter:
    """技术栈指纹识别"""
    
    FINGERPRINTS = {
        'frontend': {
            'Vue.js': [r'vue(@|/)', r'chunk-vendors', r'__VUE__', r'Vue\.js', r'create-vue'],
            'React': [r'react(@|/)', r'__REACT__', r'create-react-app', r'nextjs'],
            'Angular': [r'@angular', r'ng-version', r'Angular', r'zone\.js'],
            'jQuery': [r'jquery', r'\.jquery', r'jQuery'],
            'Bootstrap': [r'bootstrap', r'bootstrap\.js'],
        },
        'backend': {
            'Spring': [r'Spring', r'springframework', r'jvm'],
            'Django': [r'django', r'CSRF_COOKIE', r'csrftoken'],
            'Flask': [r'flask', r'Werkzeug'],
            'Express': [r'express', r'Node\.js'],
            'FastAPI': [r'fastapi', r'Swagger/FastAPI'],
            'Laravel': [r'laravel', r'laravel_session'],
            'Tomcat': [r'Apache-Coyote', r'tomcat'],
            'Nginx': [r'nginx', r'nginx/'],
            'Apache': [r'apache', r'Apache/'],
        },
        'api': {
            'GraphQL': [r'graphql', r'__schema', r'GraphQL'],
            'REST': [r'/api/', r'/v1/', r'/v2/'],
            'gRPC': [r'grpc', r'protocolbuffers'],
            'WebSocket': [r'websocket', r'SocketIO'],
            'Socket.IO': [r'socket\.io', r'SocketIO'],
        }
    }
    
    def __init__(self, session: requests.Session = None):
        self.session = session
    
    def fingerprint_from_response(self, url: str) -> Dict[str, Set[str]]:
        """从响应中识别技术栈"""
        result = {
            'frontend': set(),
            'backend': set(),
            'api': set()
        }
        
        try:
            resp = self.session.get(url, timeout=5)
            content = resp.text
            headers = dict(resp.headers)
            header_str = str(headers).lower()
            
            for category, patterns in self.FINGERPRINTS.items():
                for tech, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, header_str, re.IGNORECASE):
                            result[category].add(tech)
                            
        except Exception:
            pass
        
        return {k: list(v) for k, v in result.items()}
    
    def fingerprint_from_js(self, js_content: str) -> Dict[str, Set[str]]:
        """从 JS 中识别技术栈"""
        result = {
            'frontend': set(),
            'backend': set(),
            'api': set()
        }
        
        for category, patterns in self.FINGERPRINTS.items():
            for tech, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, js_content, re.IGNORECASE):
                        result[category].add(tech)
        
        return {k: list(v) for k, v in result.items()}


class ResponseDifferentialAnalyzer:
    """响应差异分析器"""
    
    def __init__(self, session: requests.Session = None):
        self.session = session
        self.baseline_response = None
        self.baseline_hash = ""
    
    def set_baseline(self, url: str):
        """设置基线响应"""
        try:
            resp = self.session.get(url, timeout=5)
            self.baseline_response = resp
            import hashlib
            self.baseline_hash = hashlib.md5(resp.content).hexdigest()
        except Exception:
            pass
    
    def analyze(self, url: str, params: Dict = None) -> Dict:
        """分析响应差异"""
        result = {
            'is_different': False,
            'status_changed': False,
            'length_diff': 0,
            'content_hash': '',
            'interesting': False,
            'reason': ''
        }
        
        try:
            if params:
                resp = self.session.post(url, json=params, timeout=5)
            else:
                resp = self.session.get(url, timeout=5)
            
            import hashlib
            content_hash = hashlib.md5(resp.content).hexdigest()
            result['content_hash'] = content_hash
            
            if content_hash != self.baseline_hash:
                result['is_different'] = True
                result['length_diff'] = len(resp.content) - len(self.baseline_response.content)
            
            if resp.status_code != self.baseline_response.status_code:
                result['status_changed'] = True
            
            if result['is_different'] and abs(result['length_diff']) > 100:
                result['interesting'] = True
                result['reason'] = 'Significant content difference'
            
            if result['status_changed']:
                result['interesting'] = True
                result['reason'] = f'Status changed: {self.baseline_response.status_code} -> {resp.status_code}'
                
        except Exception:
            pass
        
        return result


class SubdomainEnumerator:
    """子域名枚举"""
    
    COMMON_SUBDOMAINS = [
        'api', 'api1', 'api2', 'dev', 'test', 'staging', 'prod',
        'admin', 'adm', 'manage', 'dashboard',
        'auth', 'login', 'sso', 'oauth',
        'cdn', 'static', 'assets', 'img', 'images',
        'mail', 'smtp', 'pop', 'imap',
        'ftp', 'sftp', 'ssh', 'vpn',
        'git', 'svn', 'ci', 'cd', 'jenkins',
        'db', 'database', 'mysql', 'postgres', 'mongo',
        'redis', 'memcache', 'cache',
        'search', 'elasticsearch', 'solr',
        'queue', 'kafka', 'rabbitmq',
        'k8s', 'kubernetes', 'docker', 'registry',
        'backup', 'backup1', 'backups',
        'office', 'corp', 'internal', 'intranet',
        'mobile', 'm', 'app',
        'docs', 'doc', 'wiki',
        'status', 'monitor', 'health',
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session
    
    def enumerate(self, domain: str, check_availability: bool = True) -> List[str]:
        """枚举子域名"""
        subdomains = []
        
        base_domain = self._extract_base_domain(domain)
        
        for sub in self.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{base_domain}"
            
            if check_availability:
                try:
                    resp = self.session.get(
                        f"http://{subdomain}",
                        timeout=3,
                        allow_redirects=True
                    )
                    if resp.status_code < 500:
                        subdomains.append(subdomain)
                except Exception:
                    pass
            else:
                subdomains.append(subdomain)
        
        return subdomains
    
    def enumerate_via_dns(self, domain: str) -> List[str]:
        """通过 DNS 枚举子域名"""
        subdomains = []
        
        if not HAS_DNS:
            return subdomains
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            
            for sub in self.COMMON_SUBDOMAINS[:20]:
                subdomain = f"{sub}.{domain}"
                
                try:
                    answers = resolver.resolve(subdomain, 'A')
                    if answers:
                        for rdata in answers:
                            subdomains.append(f"{subdomain} -> {rdata}")
                except:
                    pass
                    
        except Exception:
            pass
        
        return subdomains
    
    def _extract_base_domain(self, domain: str) -> str:
        """提取主域名"""
        parts = domain.split('.')
        
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        return domain


class ErrorLeakAnalyzer:
    """错误信息泄露分析"""
    
    ERROR_PATTERNS = {
        'SQL Error': [
            r'sql\s*syntax',
            r'mysql.*error',
            r'postgresql.*error',
            r'microsoft.*sql',
            r'ora-\d{5}',
            r'sqlite.*error',
        ],
        'Path Traversal': [
            r'\.\.(\/|\\)',
            r'path.*not.*found',
            r'file.*not.*found',
            r'cannot.*read',
        ],
        'Command Injection': [
            r'system\(\)',
            r'exec\(\)',
            r'shell_exec',
            r'passthru',
            r'popen',
        ],
        'XXE': [
            r'<!ENTITY',
            r'<!DOCTYPE.*\[',
            r'SimpleXMLElement',
        ],
        'SSRF': [
            r'url=',
            r'fetch=',
            r'request=',
            r'endpoint=',
        ],
        'IDOR': [
            r'user.*not.*found',
            r'access.*denied',
            r'unauthorized',
            r'forbidden',
        ],
        'Information Disclosure': [
            r'file://',
            r'php://',
            r'http://',
            r'https://',
            r'localhost',
            r'127\.0\.0\.1',
            r'/etc/passwd',
            r'c:\\windows',
        ]
    }
    
    def __init__(self, session: requests.Session = None):
        self.session = session
    
    def analyze_response(self, url: str, response_text: str) -> List[Dict]:
        """分析响应中的错误泄露"""
        leaks = []
        
        for error_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    context = response_text[start:end]
                    
                    leaks.append({
                        'type': error_type,
                        'pattern': pattern,
                        'context': context,
                        'url': url
                    })
        
        return leaks
    
    def fuzz_and_analyze(self, url: str, method: str = 'GET') -> List[Dict]:
        """Fuzz 并分析错误"""
        leaks = []
        
        fuzz_payloads = {
            'sql': ["'", "1 OR 1=1", "1 AND 1=1", "1 UNION SELECT"],
            'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'path': ["../etc/passwd", "..\\..\\windows\\win.ini"],
            'cmd': ["; ls", "| cat /etc/passwd", "&& whoami"],
        }
        
        for payload_type, payloads in fuzz_payloads.items():
            for payload in payloads:
                try:
                    if method == 'GET':
                        resp = self.session.get(url, params={'q': payload}, timeout=5)
                    else:
                        resp = self.session.post(url, data={'q': payload}, timeout=5)
                    
                    leak = self.analyze_response(url, resp.text)
                    leaks.extend(leak)
                    
                except Exception:
                    pass
        
        return leaks


class AdvancedRecon:
    """
    高级侦察引擎
    
    整合多种侦察方法，参考渗透测试工程师的完整流程：
    """
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        
        self.swagger = SwaggerDiscoverer(session)
        self.websocket = WebSocketDiscoverer(session)
        self.fingerprinter = TechFingerprinter(session)
        self.diff_analyzer = ResponseDifferentialAnalyzer(session)
        self.subdomain_enum = SubdomainEnumerator(session)
        self.error_analyzer = ErrorLeakAnalyzer(session)
        
        self.result = ReconResult()
    
    def run(self, target_url: str) -> ReconResult:
        """执行完整侦察流程"""
        print("[*] Starting advanced reconnaissance...")
        
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        print(f"[*] Discovering Swagger/OpenAPI...")
        swagger_results = self.swagger.discover(target_url)
        self.result.swagger_endpoints = [s['url'] for s in swagger_results]
        
        print(f"[*] Fingerprinting tech stack...")
        tech_stack = self.fingerprinter.fingerprint_from_response(target_url)
        self.result.tech_stack = tech_stack
        
        print(f"[*] Enumerating subdomains...")
        subdomains = self.subdomain_enum.enumerate(domain, check_availability=False)
        self.result.subdomains = set(subdomains)
        
        print(f"[*] Discovering WebSocket endpoints...")
        try:
            resp = self.session.get(target_url, timeout=5)
            ws_urls = self.websocket.discover_from_js(resp.text, target_url)
            self.result.websocket_urls = ws_urls
        except:
            pass
        
        print(f"[*] Analyzing API patterns...")
        for endpoint in self._discover_api_patterns(target_url):
            self.result.api_patterns.add(endpoint)
        
        print(f"[*] Collecting interesting URLs...")
        self.result.interesting_urls = self._collect_interesting_urls(target_url)
        
        return self.result
    
    def _discover_api_patterns(self, base_url: str) -> List[str]:
        """发现 API 模式"""
        patterns = []
        
        pattern_tests = [
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest',
            '/graphql',
            '/rpc',
        ]
        
        for pattern in pattern_tests:
            url = base_url.rstrip('/') + pattern
            try:
                resp = self.session.head(url, timeout=3, allow_redirects=False)
                if resp.status_code < 500:
                    patterns.append(pattern)
            except:
                pass
        
        return patterns
    
    def _collect_interesting_urls(self, base_url: str) -> List[str]:
        """收集有趣的 URL"""
        urls = []
        
        interesting_paths = [
            '/admin', '/login', '/register', '/password/reset',
            '/api', '/api-docs', '/swagger', '/openapi',
            '/.git/config', '/.env', '/config', '/settings',
            '/debug', '/test', '/debug/pprof',
            '/actuator', '/env', '/heapdump',
        ]
        
        for path in interesting_paths:
            url = base_url.rstrip('/') + path
            try:
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 401, 403, 500]:
                    urls.append(f"{path} -> {resp.status_code}")
            except:
                pass
        
        return urls


def run_full_recon(target_url: str) -> Dict:
    """运行完整侦察"""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    recon = AdvancedRecon(session)
    result = recon.run(target_url)
    
    swagger_details = []
    for url in result.swagger_endpoints:
        details = recon.swagger.parse_swagger(url)
        if details:
            swagger_details.append(details)
    
    return {
        'target': target_url,
        'tech_stack': result.tech_stack,
        'swagger_endpoints': result.swagger_endpoints,
        'swagger_details': swagger_details,
        'websocket_urls': result.websocket_urls,
        'subdomains': list(result.subdomains),
        'api_patterns': list(result.api_patterns),
        'interesting_urls': result.interesting_urls,
        'error_leaks': result.error_leaks,
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.65.100.160:6004"
    
    result = run_full_recon(target)
    
    print("\n" + "=" * 70)
    print(" Advanced Recon Results")
    print("=" * 70)
    
    print(f"\n[*] Tech Stack:")
    for category, techs in result['tech_stack'].items():
        if techs:
            print(f"    {category}: {', '.join(techs)}")
    
    print(f"\n[*] Swagger/OpenAPI: {len(result['swagger_endpoints'])}")
    for ep in result['swagger_endpoints']:
        print(f"    - {ep}")
    
    print(f"\n[*] WebSocket: {len(result['websocket_urls'])}")
    for ws in result['websocket_urls'][:5]:
        print(f"    - {ws}")
    
    print(f"\n[*] Subdomains: {len(result['subdomains'])}")
    for sub in list(result['subdomains'])[:10]:
        print(f"    - {sub}")
    
    print(f"\n[*] API Patterns: {len(result['api_patterns'])}")
    for pattern in result['api_patterns']:
        print(f"    - {pattern}")
    
    print(f"\n[*] Interesting URLs: {len(result['interesting_urls'])}")
    for url in result['interesting_urls'][:10]:
        print(f"    - {url}")
    
    if result['swagger_details']:
        print(f"\n[*] Swagger Details:")
        for details in result['swagger_details']:
            print(f"    Title: {details.get('title', 'N/A')}")
            print(f"    Version: {details.get('version', 'N/A')}")
            print(f"    Endpoints: {details.get('total', 0)}")
