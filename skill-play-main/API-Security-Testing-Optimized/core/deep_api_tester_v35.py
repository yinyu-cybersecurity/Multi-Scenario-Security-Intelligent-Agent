#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度 API 渗透测试引擎 v3.5
- 递归分析所有 JS (包括 chunk)
- 全量流量捕获和提取
- 提取参数/接口/敏感信息/登录凭证
- 智能关联分析
"""

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
import re
import json
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import hashlib

class DeepAPITester:
    """深度 API 测试引擎 v3.5"""
    
    def __init__(self, target: str, headless: bool = True, max_depth: int = 3):
        self.target = target.rstrip('/')
        self.headless = headless
        self.max_depth = max_depth
        
        # 存储数据
        self.all_js_files: Set[str] = set()
        self.all_api_endpoints: List[Dict] = []
        self.all_traffic: List[Dict] = []
        self.secrets: List[Dict] = []
        self.credentials: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        
        # HTTP 会话
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        
        # JS 分析缓存
        self.analyzed_js: Set[str] = set()
    
    def crawl_with_browser(self) -> Dict:
        """使用无头浏览器爬取，全量捕获流量"""
        print(f"\n{'='*70}")
        print(f"[+] 使用无头浏览器爬取：{self.target}")
        print(f"{'='*70}\n")
        
        traffic_log = []
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True
            )
            page = context.new_page()
            
            # 拦截所有请求和响应
            def handle_request(request):
                url = request.url
                method = request.method
                resource_type = request.resource_type
                
                # 记录所有请求
                request_data = {
                    'timestamp': time.time(),
                    'url': url,
                    'method': method,
                    'resource_type': resource_type,
                    'headers': dict(request.headers),
                    'post_data': request.post_data,
                    'params': self._extract_params(url, method, request.post_data)
                }
                
                traffic_log.append(request_data)
                self.all_traffic.append(request_data)
                
                # 分类处理
                if resource_type == 'script':
                    self.all_js_files.add(url)
                    print(f"  [JS] {url}")
                
                elif self._is_api_request(url):
                    self.all_api_endpoints.append(request_data)
                    print(f"  [API] {method} {url}")
            
            def handle_response(response):
                url = response.url
                status = response.status
                
                # 检查响应中的敏感信息
                try:
                    body = response.text()
                    self._analyze_response_body(url, body)
                except:
                    pass
            
            page.on('request', handle_request)
            page.on('response', handle_response)
            
            try:
                # 访问目标页面
                print(f"[*] 访问目标页面...")
                page.goto(self.target, wait_until='networkidle', timeout=30000)
                
                # 等待 JS 执行
                print(f"[*] 等待 JS 执行 (5 秒)...")
                page.wait_for_timeout(5000)
                
                # 递归探索页面
                print(f"[*] 递归探索页面 (深度：{self.max_depth})...")
                self._recursive_explore(page, depth=0)
                
                # 提取 JS 文件
                print(f"[*] 提取所有 JS 文件...")
                js_from_dom = self._extract_all_js_from_dom(page)
                self.all_js_files.update(js_from_dom)
                
                # 执行 JS 提取路由
                print(f"[*] 从 JS 中提取路由和 API...")
                self._extract_routes_and_apis_from_all_js()
                
            except PlaywrightTimeout:
                print(f"[!] 页面加载超时")
            except Exception as e:
                print(f"[!] 错误：{e}")
            finally:
                browser.close()
        
        return {
            'js_files': len(self.all_js_files),
            'api_endpoints': len(self.all_api_endpoints),
            'traffic': len(self.all_traffic)
        }
    
    def _recursive_explore(self, page, depth: int = 0):
        """递归探索页面，触发更多 API"""
        if depth >= self.max_depth:
            return
        
        print(f"  [深度 {depth}] 探索页面...")
        
        # 点击所有可点击元素
        clickable_selectors = [
            'button', 'a[href]', 'input[type="button"]', 
            'input[type="submit"]', '.btn', '[role="button"]',
            '.clickable', '[onclick]'
        ]
        
        for selector in clickable_selectors:
            try:
                elements = page.query_selector_all(selector)
                for elem in elements[:20]:  # 限制数量
                    try:
                        elem.click()
                        page.wait_for_timeout(1000)
                        page.wait_for_load_state('networkidle', timeout=5000)
                    except:
                        pass
            except:
                pass
        
        # 滚动页面
        try:
            page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
            page.wait_for_timeout(2000)
            page.evaluate('window.scrollTo(0, 0)')
            page.wait_for_timeout(1000)
        except:
            pass
        
        # 填写表单并提交
        try:
            forms = page.query_selector_all('form')
            for form in forms[:5]:
                try:
                    # 尝试填写测试数据
                    inputs = form.query_selector_all('input[type="text"], input[type="email"]')
                    for inp in inputs[:3]:
                        try:
                            inp.fill('test@example.com')
                        except:
                            pass
                    
                    # 点击提交
                    submit_btn = form.query_selector('input[type="submit"], button[type="submit"]')
                    if submit_btn:
                        submit_btn.click()
                        page.wait_for_timeout(2000)
                except:
                    pass
        except:
            pass
        
        # 递归
        if depth < self.max_depth - 1:
            self._recursive_explore(page, depth + 1)
    
    def _extract_all_js_from_dom(self, page) -> Set[str]:
        """从 DOM 提取所有 JS 文件"""
        js_files = page.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script');
                const jsFiles = new Set();
                
                scripts.forEach(script => {
                    // 外部 JS
                    if (script.src) {
                        jsFiles.add(script.src);
                    }
                    
                    // 内联 JS 中的动态加载
                    if (script.textContent) {
                        const matches = script.textContent.match(/['"`](https?:\\/\\/[^'"`]+\\.js[^'"`]*)['"`]/g);
                        if (matches) {
                            matches.forEach(m => jsFiles.add(m.replace(/['"`]/g, '')));
                        }
                    }
                });
                
                // 从 window 对象获取
                if (window.webpackChunk) {
                    // Webpack chunk 加载逻辑
                }
                
                return Array.from(jsFiles);
            }
        """)
        
        # 转换为绝对 URL
        absolute_js = set()
        for js in js_files:
            if js.startswith('//'):
                js = 'https:' + js
            elif js.startswith('/'):
                js = self.target + js
            elif not js.startswith('http'):
                js = urljoin(self.target, js)
            
            if '.js' in js:
                absolute_js.add(js)
        
        print(f"  [+] 发现 {len(absolute_js)} 个 JS 文件")
        return absolute_js
    
    def _extract_routes_and_apis_from_all_js(self):
        """从所有 JS 文件提取路由和 API"""
        print(f"\n{'='*70}")
        print(f"[+] 全量 JS 分析 ({len(self.all_js_files)} 个文件)")
        print(f"{'='*70}\n")
        
        for js_url in self.all_js_files:
            if js_url in self.analyzed_js:
                continue
            
            self.analyzed_js.add(js_url)
            
            try:
                print(f"  [*] 分析：{js_url[:100]}...")
                response = self.session.get(js_url, timeout=10)
                content = response.text
                
                # 提取 API 端点
                endpoints = self._extract_apis_from_js(content, js_url)
                for endpoint in endpoints:
                    # 检查是否已存在
                    exists = any(
                        e.get('url', '') == endpoint.get('url', '') and 
                        e.get('method', '') == endpoint.get('method', '')
                        for e in self.all_api_endpoints
                    )
                    if not exists:
                        self.all_api_endpoints.append(endpoint)
                        print(f"    [API] {endpoint.get('method', 'GET')} {endpoint.get('url', '')}")
                
                # 提取敏感信息
                secrets = self._extract_secrets_from_js(content, js_url)
                self.secrets.extend(secrets)
                
                # 提取凭证
                creds = self._extract_credentials_from_js(content, js_url)
                self.credentials.extend(creds)
                
            except Exception as e:
                print(f"    [!] 分析失败：{e}")
    
    def _extract_apis_from_js(self, content: str, source: str) -> List[Dict]:
        """从 JS 内容提取 API 端点"""
        apis = []
        
        # 全面的 API 提取正则
        patterns = [
            # axios
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'axios'),
            (r'axios\s*\(\s*\{\s*method:\s*[\'"`]?(get|post|put|delete|patch)[\'"`]?', 'axios_config'),
            
            # fetch
            (r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'fetch'),
            (r'fetch\s*\(\s*new\s+Request\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'fetch_request'),
            
            # XMLHttpRequest
            (r'\.open\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]', 'xhr'),
            
            # Vue resource
            (r'this\.\$http\.(get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'vue_http'),
            (r'this\.\$axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'vue_axios'),
            
            # Angular http
            (r'this\.http\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'angular_http'),
            
            # 通用路由
            (r'[\'"`](/api/[^\'"`\s?#]+)[\'"`]', 'api_path'),
            (r'[\'"`](/rest/[^\'"`\s?#]+)[\'"`]', 'rest_path'),
            (r'[\'"`](/service/[^\'"`\s?#]+)[\'"`]', 'service_path'),
            (r'[\'"`](/do/[^\'"`\s?#]+)[\'"`]', 'do_path'),
            (r'[\'"`](/action/[^\'"`\s?#]+)[\'"`]', 'action_path'),
            
            # 路由配置
            (r'path:\s*[\'"`]([^\'"`]+)[\'"`]', 'vue_router'),
            (r'component:\s*.*?import\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'lazy_route'),
            
            # 完整 URL
            (r'(https?://[^\'"`\s]+/api/[^\'"`\s]+)', 'full_url'),
        ]
        
        for pattern, pattern_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    method = match[0].upper() if match[0].lower() in ['get', 'post', 'put', 'delete', 'patch'] else 'GET'
                    url = match[1] if len(match) > 1 else match[0]
                else:
                    method = 'GET'
                    url = match
                
                # 清理 URL
                url = url.replace('${', '{').replace('}', '').replace('${', '')
                
                # 转换为绝对 URL
                if url.startswith('/'):
                    url = self.target + url
                elif not url.startswith('http'):
                    url = urljoin(self.target, url)
                
                # 提取参数
                params = self._extract_params_from_url(url)
                
                apis.append({
                    'url': url,
                    'method': method,
                    'source': source,
                    'pattern_type': pattern_type,
                    'params': params,
                    'discovered_by': 'js_analysis'
                })
        
        return apis
    
    def _extract_secrets_from_js(self, content: str, source: str) -> List[Dict]:
        """从 JS 提取敏感信息"""
        secrets = []
        
        patterns = {
            'api_key': [
                r'(?:api[_-]?key|apikey)\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
                r'API_KEY\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'appKey\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
            'token': [
                r'(?:token|auth[_-]?token|access[_-]?token)\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
                r'TOKEN\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'Bearer\s+[\'"`]([^\'"`]+)[\'"`]',
            ],
            'password': [
                r'(?:password|passwd|pwd)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'PASSWORD\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
            'secret': [
                r'(?:secret|secret[_-]?key)\s*[=:]\s*[\'"`]([^\'"`]{8,})[\'"`]',
                r'SECRET\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
            'aws': [
                r'(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}',
                r'aws[_-]?access[_-]?key\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
            'database': [
                r'(?:mongodb|mysql|postgresql|redis)://[^\s\'"`]+',
                r'DB_CONNECTION\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
            'private_key': [
                r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
                r'private[_-]?key\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            ],
        }
        
        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    secrets.append({
                        'type': secret_type,
                        'value': match[:100] + '...' if len(match) > 100 else match,
                        'source': source,
                        'severity': self._get_secret_severity(secret_type)
                    })
                    print(f"    [!] 敏感信息 [{secret_type}]: {match[:30]}...")
        
        return secrets
    
    def _extract_credentials_from_js(self, content: str, source: str) -> List[Dict]:
        """提取登录凭证"""
        credentials = []
        
        # 查找登录相关代码
        login_patterns = [
            r'username\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'password\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'account\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'credentials\s*[=:]\s*\{[^}]*username\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`][^}]*password\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        for pattern in login_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    credentials.append({
                        'username': match[0],
                        'password': match[1] if len(match) > 1 else match[0],
                        'source': source
                    })
                else:
                    credentials.append({
                        'username': match,
                        'password': '',
                        'source': source
                    })
        
        return credentials
    
    def _analyze_response_body(self, url: str, body: str):
        """分析响应体，提取敏感信息"""
        # 检查 JSON 响应
        if 'application/json' in str(self.session.headers.get('Content-Type', '')):
            try:
                data = json.loads(body)
                self._check_json_for_secrets(url, data)
            except:
                pass
        
        # 检查敏感数据模式
        sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b1[3-9]\d{9}\b',
            'id_card': r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
            'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        }
        
        for data_type, pattern in sensitive_patterns.items():
            if re.search(pattern, body):
                self.vulnerabilities.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': 'MEDIUM',
                    'endpoint': url,
                    'data_type': data_type,
                    'evidence': f'Found {data_type} in response'
                })
    
    def _check_json_for_secrets(self, url: str, data: Dict):
        """检查 JSON 中的敏感数据"""
        sensitive_keys = ['password', 'token', 'secret', 'api_key', 'private_key', 'credential']
        
        def check_dict(d: Dict, path: str = ''):
            for key, value in d.items():
                current_path = f"{path}.{key}" if path else key
                
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    self.secrets.append({
                        'type': 'json_sensitive_data',
                        'key': current_path,
                        'value': str(value)[:50] + '...' if len(str(value)) > 50 else str(value),
                        'source': url
                    })
                
                if isinstance(value, dict):
                    check_dict(value, current_path)
        
        check_dict(data)
    
    def _extract_params(self, url: str, method: str, post_data: str = None) -> Dict:
        """从请求提取参数"""
        params = {}
        
        # URL 参数
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        if url_params:
            params['query'] = url_params
        
        # POST 数据
        if post_data:
            try:
                if post_data.startswith('{'):
                    params['body'] = json.loads(post_data)
                else:
                    params['body'] = parse_qs(post_data)
            except:
                params['body_raw'] = post_data
        
        return params
    
    def _extract_params_from_url(self, url: str) -> List[str]:
        """从 URL 提取参数占位符"""
        # 提取 {param} 或 :param 形式的参数
        patterns = [
            r'\{([^}]+)\}',
            r':([a-zA-Z_][a-zA-Z0-9_]*)'
        ]
        
        params = []
        for pattern in patterns:
            matches = re.findall(pattern, url)
            params.extend(matches)
        
        return list(set(params))
    
    def _is_api_request(self, url: str) -> bool:
        """判断是否是 API 请求"""
        api_indicators = [
            '/api/', '/api/v', '/rest/', '/graphql', '/graph',
            '/service/', '/do/', '/action/', '/controller/',
            '.json', '.action', '.do', '.api',
            'controller', 'service', 'api', 'rest'
        ]
        return any(indicator in url.lower() for indicator in api_indicators)
    
    def _get_secret_severity(self, secret_type: str) -> str:
        """获取敏感信息严重程度"""
        severity_map = {
            'private_key': 'CRITICAL',
            'aws': 'CRITICAL',
            'database': 'CRITICAL',
            'password': 'HIGH',
            'token': 'HIGH',
            'secret': 'HIGH',
            'api_key': 'MEDIUM',
        }
        return severity_map.get(secret_type, 'MEDIUM')
    
    def scan_vulnerabilities(self):
        """漏洞扫描"""
        print(f"\n{'='*70}")
        print(f"[+] 漏洞扫描")
        print(f"{'='*70}\n")
        
        # 去重端点
        unique_endpoints = defaultdict(set)
        for endpoint in self.all_api_endpoints:
            parsed = urlparse(endpoint['url'])
            unique_endpoints[parsed.path].add(endpoint.get('method', 'GET'))
        
        # SQL 注入
        print(f"[*] SQL 注入测试 ({len(unique_endpoints)} 个端点)...")
        self._test_sqli(unique_endpoints)
        
        # XSS
        print(f"[*] XSS 测试...")
        self._test_xss(unique_endpoints)
        
        # 未授权访问
        print(f"[*] 未授权访问测试...")
        self._test_unauthorized_access(unique_endpoints)
        
        # 敏感数据
        print(f"[*] 敏感数据泄露测试...")
        self._test_data_exposure()
        
        # 硬编码凭证
        if self.credentials:
            print(f"[*] 测试硬编码凭证...")
            self._test_hardcoded_credentials()
    
    def _test_sqli(self, endpoints: Dict[str, Set[str]]):
        """SQL 注入测试"""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--"
        ]
        
        sqli_errors = [
            'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
            'SQLite', 'ODBC', 'jdbc', 'hibernate', 'sqlserver'
        ]
        
        for path, methods in endpoints.items():
            for method in methods:
                for payload in sqli_payloads:
                    try:
                        test_url = f"{self.target}{path}"
                        params = {'id': payload, 'search': payload, 'user': payload}
                        
                        if method == 'GET':
                            response = self.session.get(test_url, params=params, timeout=10)
                        else:
                            response = self.session.post(test_url, data=params, timeout=10)
                        
                        for error in sqli_errors:
                            if error.lower() in response.text.lower():
                                self.vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'endpoint': path,
                                    'method': method,
                                    'payload': payload,
                                    'evidence': error
                                })
                                print(f"  [!] SQL 注入：{path}")
                                break
                    
                    except:
                        pass
    
    def _test_xss(self, endpoints: Dict[str, Set[str]]):
        """XSS 测试"""
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>'
        ]
        
        for path, methods in endpoints.items():
            for payload in xss_payloads:
                try:
                    test_url = f"{self.target}{path}"
                    params = {'q': payload, 'search': payload, 'name': payload}
                    
                    response = self.session.get(test_url, params=params, timeout=10)
                    
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'XSS (Reflected)',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'payload': payload,
                            'evidence': 'Payload reflected'
                        })
                        print(f"  [!] XSS: {path}")
                
                except:
                    pass
    
    def _test_unauthorized_access(self, endpoints: Dict[str, Set[str]]):
        """未授权访问测试"""
        sensitive_paths = ['/admin', '/api/user', '/api/config', '/api/admin', '/manage']
        
        for path in sensitive_paths:
            if path in endpoints:
                try:
                    test_url = f"{self.target}{path}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Unauthorized Access',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'evidence': f'Status: {response.status_code}'
                        })
                        print(f"  [!] 未授权访问：{path}")
                
                except:
                    pass
    
    def _test_data_exposure(self):
        """敏感数据暴露测试"""
        for secret in self.secrets:
            if secret.get('severity') in ['CRITICAL', 'HIGH']:
                self.vulnerabilities.append({
                    'type': 'Sensitive Data Exposure',
                    'severity': secret.get('severity', 'MEDIUM'),
                    'endpoint': secret.get('source', 'Unknown'),
                    'data_type': secret.get('type', 'unknown'),
                    'evidence': secret.get('value', '')[:100]
                })
    
    def _test_hardcoded_credentials(self):
        """测试硬编码凭证"""
        for cred in self.credentials:
            username = cred.get('username', '')
            password = cred.get('password', '')
            
            if username and password:
                # 尝试登录
                try:
                    login_url = f"{self.target}/login"
                    response = self.session.post(login_url, data={
                        'username': username,
                        'password': password
                    }, timeout=10)
                    
                    if response.status_code == 200 and 'token' in response.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Hardcoded Credentials',
                            'severity': 'CRITICAL',
                            'endpoint': '/login',
                            'username': username,
                            'password': password,
                            'evidence': 'Credentials work'
                        })
                        print(f"  [!] 硬编码凭证有效：{username}:{password}")
                
                except:
                    pass
    
    def generate_report(self, output_file: str = 'deep_test_report.md'):
        """生成详细报告"""
        report = f"""# 深度 API 渗透测试报告 v3.5

## 执行摘要
- **测试目标**: {self.target}
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}
- **测试工具**: Deep API Tester v3.5
- **测试深度**: {self.max_depth} 层

## 发现统计
| 类型 | 数量 |
|------|------|
| JS 文件 | {len(self.all_js_files)} |
| API 端点 | {len(self.all_api_endpoints)} |
| 捕获流量 | {len(self.all_traffic)} |
| 敏感信息 | {len(self.secrets)} |
| 登录凭证 | {len(self.credentials)} |
| 漏洞数量 | {len(self.vulnerabilities)} |

## JS 文件列表
"""
        
        # JS 文件
        for js in sorted(self.all_js_files):
            report += f"- `{js}`\n"
        
        # API 端点
        report += f"\n## API 端点列表\n"
        endpoints_grouped = defaultdict(list)
        for endpoint in self.all_api_endpoints:
            parsed = urlparse(endpoint['url'])
            endpoints_grouped[parsed.path].append(endpoint.get('method', 'GET'))
        
        for path, methods in sorted(endpoints_grouped.items()):
            report += f"- `{', '.join(set(methods))} {path}`\n"
        
        # 敏感信息
        if self.secrets:
            report += f"\n## 敏感信息\n"
            for secret in self.secrets:
                report += f"- **[{secret.get('severity', 'MEDIUM')}]** {secret.get('type', 'unknown')}: `{secret.get('value', '')[:50]}...`\n"
                report += f"  - 来源：{secret.get('source', 'Unknown')}\n"
        
        # 登录凭证
        if self.credentials:
            report += f"\n## 登录凭证\n"
            for cred in self.credentials:
                report += f"- Username: `{cred.get('username', '')}`\n"
                report += f"  - Password: `{cred.get('password', '')}`\n"
                report += f"  - 来源：{cred.get('source', 'Unknown')}\n"
        
        # 漏洞详情
        report += f"\n## 漏洞详情\n"
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                report += f"""
### {vuln['type']}
- **严重程度**: {vuln['severity']}
- **端点**: {vuln.get('endpoint', 'N/A')}
- **方法**: {vuln.get('method', 'N/A')}
- **证据**: {vuln.get('evidence', 'N/A')[:200]}
"""
        else:
            report += "\n未发现明显漏洞。\n"
        
        # 保存报告
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n[+] 报告已保存：{output_file}")
        return report
    
    def run_full_test(self, output_file: str = 'deep_test_report.md'):
        """执行完整测试"""
        print(f"\n{'='*70}")
        print(f"深度 API 渗透测试 v3.5")
        print(f"目标：{self.target}")
        print(f"{'='*70}\n")
        
        # 1. 浏览器爬取
        crawl_result = self.crawl_with_browser()
        
        # 2. 漏洞扫描
        self.scan_vulnerabilities()
        
        # 3. 生成报告
        self.generate_report(output_file)
        
        print(f"\n{'='*70}")
        print(f"测试完成！")
        print(f"JS 文件：{crawl_result['js_files']}")
        print(f"API 端点：{crawl_result['api_endpoints']}")
        print(f"捕获流量：{crawl_result['traffic']}")
        print(f"发现漏洞：{len(self.vulnerabilities)}")
        print(f"{'='*70}\n")
        
        return {
            'js_files': crawl_result['js_files'],
            'api_endpoints': crawl_result['api_endpoints'],
            'traffic': crawl_result['traffic'],
            'secrets': len(self.secrets),
            'credentials': len(self.credentials),
            'vulnerabilities': len(self.vulnerabilities)
        }


# CLI 入口
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python deep_api_tester_v35.py <target_url> [output_file] [max_depth]")
        print("Example: python deep_api_tester_v35.py http://example.com report.md 3")
        sys.exit(1)
    
    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else 'deep_test_report.md'
    max_depth = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    
    tester = DeepAPITester(target, max_depth=max_depth)
    tester.run_full_test(output)
