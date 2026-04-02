#!/usr/bin/env python3
"""
Smart API Analyzer - 智能 API 分析器
参考 ApiRed + 渗透测试工程师思维

核心功能：
1. 从 JS 中精确提取后端 API (过滤前端路由)
2. 识别参数定义和类型
3. 智能分类 API 端点
4. 敏感信息挖掘
5. 基于理解生成精准 fuzzing 目标
"""

import re
import hashlib
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs
from enum import Enum
import requests


class EndpointType(Enum):
    """端点类型"""
    BACKEND_API = "backend_api"      # 后端 API (有价值)
    FRONTEND_ROUTE = "frontend_route" # 前端路由 (无价值)
    STATIC_RESOURCE = "static"       # 静态资源
    UNKNOWN = "unknown"


class Sensitivity(Enum):
    """敏感等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ParsedParameter:
    """解析出的参数"""
    name: str
    param_type: str  # path, query, body, json
    data_type: str   # int, string, bool, object
    required: bool = False
    is_sensitive: bool = False
    source: str = ""  # from_response, from_js, from猜测


@dataclass
class SmartEndpoint:
    """智能端点"""
    path: str
    method: str
    endpoint_type: EndpointType = EndpointType.UNKNOWN
    sensitivity: Sensitivity = Sensitivity.INFO
    
    # 解析出的信息
    base_url: str = ""
    parameters: List[ParsedParameter] = field(default_factory=list)
    request_body: Dict = field(default_factory=dict)
    response_pattern: str = ""
    
    # 来源
    source_file: str = ""
    source_line: int = 0
    confidence: float = 0.0
    
    # 分析结果
    is_auth_endpoint: bool = False
    is_admin_endpoint: bool = False
    is_user_data_endpoint: bool = False
    has_sensitive_params: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'method': self.method,
            'type': self.endpoint_type.value,
            'sensitivity': self.sensitivity.value,
            'base_url': self.base_url,
            'parameters': [{'name': p.name, 'type': p.param_type, 'sensitive': p.is_sensitive} for p in self.parameters],
            'is_auth': self.is_auth_endpoint,
            'is_admin': self.is_admin_endpoint,
            'confidence': self.confidence,
        }


@dataclass
class SensitiveMatch:
    """敏感信息匹配"""
    data_type: str
    value: str
    severity: Sensitivity
    context: str
    source: str


class SmartAPIAnalyzer:
    """
    智能 API 分析器
    
    核心思维：像渗透测试工程师一样思考
    1. 先理解目标 - 识别技术栈和 API 结构
    2. 精确提取 - 区分后端 API 和前端路由
    3. 发现参数 - 从响应和代码中提取参数定义
    4. 智能分类 - 按功能和安全影响分类
    5. 精准 Fuzz - 基于理解生成目标
    """
    
    # 后端 API 特征
    BACKEND_API_PATTERNS = [
        r'/api/', r'/v\d+/', r'/rest/', r'/graphql',
        r'/auth/', r'/login', r'/logout', r'/token',
        r'/admin/', r'/manage/',
        r'/user/', r'/profile/', r'/account/',
        r'/data/', r'/file/', r'/upload/', r'/download/',
        r'/config/', r'/setting/', r'/sys/',
    ]
    
    # 前端路由特征 (需过滤)
    FRONTEND_ROUTE_PATTERNS = [
        r'chunk-[a-f0-9]+\.js',
        r'\.css', r'\.svg', r'\.png', r'\.jpg',
        r'/js/', r'/css/', r'/img/', r'/assets/',
        r'/dist/', r'/build/',
        r'/node_modules/',
    ]
    
    # 敏感关键字
    SENSITIVE_KEYWORDS = {
        'password': Sensitivity.HIGH,
        'passwd': Sensitivity.HIGH,
        'secret': Sensitivity.HIGH,
        'token': Sensitivity.MEDIUM,
        'jwt': Sensitivity.MEDIUM,
        'bearer': Sensitivity.MEDIUM,
        'api_key': Sensitivity.HIGH,
        'apikey': Sensitivity.HIGH,
        'access_key': Sensitivity.HIGH,
        'private_key': Sensitivity.CRITICAL,
        'credential': Sensitivity.HIGH,
        'auth': Sensitivity.MEDIUM,
        'session': Sensitivity.MEDIUM,
        'cookie': Sensitivity.MEDIUM,
        'userid': Sensitivity.LOW,
        'user_id': Sensitivity.LOW,
        'email': Sensitivity.MEDIUM,
        'phone': Sensitivity.MEDIUM,
        'mobile': Sensitivity.MEDIUM,
        'idcard': Sensitivity.CRITICAL,
        'ssn': Sensitivity.CRITICAL,
        'credit': Sensitivity.CRITICAL,
        'bank': Sensitivity.CRITICAL,
    }
    
    # 认证相关端点
    AUTH_PATTERNS = [
        r'/auth/', r'/login', r'/logout', r'/register', r'/signup',
        r'/token', r'/refresh', r'/verify', r'/oauth', r'/sso',
        r'/session', r'/cas/', r'/saml/',
    ]
    
    # 管理后台端点
    ADMIN_PATTERNS = [
        r'/admin/', r'/manage/', r'/control/', r'/dashboard',
        r'/system/', r'/config/', r'/setting/', r'/master',
        r'/root/', r'/super/', r'/privilege',
    ]
    
    # 用户数据端点
    USER_DATA_PATTERNS = [
        r'/user/', r'/profile/', r'/account/', r'/person/',
        r'/employee/', r'/member/', r'/customer/',
        r'/order/', r'/product/', r'/transaction/',
    ]
    
    # 参数名模式 (用于从响应中提取)
    PARAM_PATTERNS = [
        r'["\']?(\w+)["\']?\s*:\s*(?:null|undefined|"[^"]*"|\'[^\']*\'|\d+)',
        r'(?:id|userId|user_id|page|token|key|type|category|name|status)\s*[=:]\s*["\']?[^"\'\s,}]+',
    ]
    
    # 响应参数提取模式
    RESPONSE_PARAM_PATTERNS = [
        r'"(\w+)":\s*(?:\{|\[|"[^"]*"|\d+|true|false|null)',
        r'"(id|code|msg|data|list|count|total|pages?)"\s*:',
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.endpoints: List[SmartEndpoint] = []
        self.sensitive_data: List[SensitiveMatch] = []
        self.base_urls: Set[str] = set()
        self.js_content_cache: Dict[str, str] = {}
    
    def analyze_js_file(self, js_url: str, content: str) -> List[SmartEndpoint]:
        """
        分析 JS 文件，提取智能端点
        
        核心算法：
        1. 提取所有字符串字面量
        2. 识别 HTTP 调用模式 (fetch, axios, etc.)
        3. 识别 Base URL 配置
        4. 区分后端 API 和前端路由
        5. 提取参数信息
        """
        endpoints = []
        
        base_url = self._extract_base_url(content, js_url)
        if base_url:
            self.base_urls.add(base_url)
        
        # 1. 提取 fetch 调用
        fetch_endpoints = self._extract_fetch_patterns(content, base_url)
        endpoints.extend(fetch_endpoints)
        
        # 2. 提取 axios 调用
        axios_endpoints = self._extract_axios_patterns(content, base_url)
        endpoints.extend(axios_endpoints)
        
        # 3. 提取 $.ajax 调用
        ajax_endpoints = self._extract_jquery_ajax_patterns(content, base_url)
        endpoints.extend(ajax_endpoints)
        
        # 4. 提取配置对象中的 URL
        config_endpoints = self._extract_config_urls(content, base_url)
        endpoints.extend(config_endpoints)
        
        # 5. 提取常量定义
        constant_endpoints = self._extract_constant_urls(content, base_url)
        endpoints.extend(constant_endpoints)
        
        # 去重
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        return unique_endpoints
    
    def _extract_base_url(self, content: str, js_url: str) -> Optional[str]:
        """提取 Base URL"""
        patterns = [
            r'(?:baseURL|base_url|apiUrl|api_url|API_URL)\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:BASE_URL|API_URL)\s*[:=]\s*["\']([^"\']+)["\']',
            r'process\.env\.([A-Z_]+)\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[-1]
                else:
                    value = match
                
                if value.startswith('http'):
                    return value.rstrip('/')
        
        parsed = urlparse(js_url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _extract_fetch_patterns(self, content: str, base_url: str) -> List[SmartEndpoint]:
        """提取 fetch 调用"""
        endpoints = []
        
        patterns = [
            (r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", "GET"),
            (r"fetch\s*\(\s*[`'\"]([^`'\"]+)[`'\"]", "GET"),
            (r"fetch\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*\{", None),
        ]
        
        for pattern, default_method in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                path = match.group(1) if match.groups() else match.group(0)
                
                if not self._is_valid_api_path(path):
                    continue
                
                method = default_method
                if method is None and match.group(0):
                    method_match = re.search(r"method:\s*['\"](\w+)['\"]", match.group(0))
                    method = method_match.group(1) if method_match else "GET"
                
                endpoint = self._create_smart_endpoint(path, method, base_url, "fetch", content)
                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_axios_patterns(self, content: str, base_url: str) -> List[SmartEndpoint]:
        """提取 axios 调用"""
        endpoints = []
        
        patterns = [
            r"axios\.(get|post|put|delete|patch|head|options)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"axios\.(get|post|put|delete|patch)\s*\(\s*[`'\"]([^`'\"]+)[`'\"]",
            r"axios\s*.\s*(?:request|post|get)\s*\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                groups = match.groups()
                if len(groups) >= 2:
                    method = groups[0].upper()
                    path = groups[1]
                    
                    if not self._is_valid_api_path(path):
                        continue
                    
                    endpoint = self._create_smart_endpoint(path, method, base_url, "axios", content)
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_jquery_ajax_patterns(self, content: str, base_url: str) -> List[SmartEndpoint]:
        """提取 $.ajax 调用"""
        endpoints = []
        
        pattern = r"\$\.ajax\s*\(\s*\{([^}]+)\}"
        matches = re.finditer(pattern, content)
        
        for match in matches:
            config = match.group(0)
            
            url_match = re.search(r"url\s*:\s*['\"]([^'\"]+)['\"]", config)
            method_match = re.search(r"type\s*:\s*['\"](\w+)['\"]", config)
            
            if url_match:
                path = url_match.group(1)
                method = method_match.group(1).upper() if method_match else "GET"
                
                if not self._is_valid_api_path(path):
                    continue
                
                endpoint = self._create_smart_endpoint(path, method, base_url, "jquery", content)
                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_config_urls(self, content: str, base_url: str) -> List[SmartEndpoint]:
        """提取配置对象中的 URL"""
        endpoints = []
        
        patterns = [
            r'(?:api|API|endpoint|ENDPOINT)\s*:\s*["\']([/a-zA-Z0-9_-]+)["\']',
            r'(?:url|URL|path|PATH)\s*:\s*["\']([/a-zA-Z0-9_-]+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for path in matches:
                if not self._is_valid_api_path(path):
                    continue
                
                endpoint = self._create_smart_endpoint(path, "GET", base_url, "config", content)
                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_constant_urls(self, content: str, base_url: str) -> List[SmartEndpoint]:
        """提取常量定义的 URL"""
        endpoints = []
        
        patterns = [
            r'const\s+\w*[Uu]rl\w*\s*=\s*["\']([^"\']+)["\']',
            r'(?:API|PATH|ROUTE)_(?:PATH|URL|ENDPOINT)\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for path in matches:
                if not self._is_valid_api_path(path):
                    continue
                
                endpoint = self._create_smart_endpoint(path, "GET", base_url, "constant", content)
                endpoints.append(endpoint)
        
        return endpoints
    
    def _is_valid_api_path(self, path: str) -> bool:
        """验证是否为有效的 API 路径"""
        if not path or len(path) < 2:
            return False
        
        if path.startswith('//') or path.startswith('http'):
            return True
        
        if path.startswith('/'):
            path = path[1:]
        
        skip_patterns = [
            r'\.js$', r'\.css$', r'\.svg$', r'\.png$', r'\.jpg$',
            r'chunk-', r'module', r'dist', r'build',
            r'node_modules', r'assets', r'images', r'icons',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return False
        
        return True
    
    def _create_smart_endpoint(self, path: str, method: str, base_url: str, source: str, content: str) -> SmartEndpoint:
        """创建智能端点"""
        endpoint = SmartEndpoint(
            path=path,
            method=method.upper(),
            base_url=base_url,
            source_file=source,
            confidence=0.8 if source in ['fetch', 'axios', 'jquery'] else 0.5
        )
        
        path_lower = path.lower()
        
        if any(re.search(p, path_lower) for p in self.AUTH_PATTERNS):
            endpoint.is_auth_endpoint = True
            endpoint.sensitivity = Sensitivity.HIGH
            endpoint.endpoint_type = EndpointType.BACKEND_API
        
        if any(re.search(p, path_lower) for p in self.ADMIN_PATTERNS):
            endpoint.is_admin_endpoint = True
            endpoint.sensitivity = Sensitivity.HIGH
            endpoint.endpoint_type = EndpointType.BACKEND_API
        
        if any(re.search(p, path_lower) for p in self.USER_DATA_PATTERNS):
            endpoint.is_user_data_endpoint = True
            endpoint.sensitivity = Sensitivity.MEDIUM
            endpoint.endpoint_type = EndpointType.BACKEND_API
        
        if endpoint.endpoint_type == EndpointType.UNKNOWN:
            if any(re.search(p, path_lower) for p in self.BACKEND_API_PATTERNS):
                endpoint.endpoint_type = EndpointType.BACKEND_API
                endpoint.sensitivity = Sensitivity.INFO
        
        endpoint.parameters = self._extract_parameters_from_content(path, content)
        
        return endpoint
    
    def _extract_parameters_from_content(self, path: str, content: str) -> List[ParsedParameter]:
        """从 JS 内容中提取参数"""
        params = []
        
        path_parts = path.strip('/').split('/')
        for i, part in enumerate(path_parts):
            if re.match(r'^\{[\w_]+\}$', part):
                param_name = part[1:-1]
                params.append(ParsedParameter(
                    name=param_name,
                    param_type='path',
                    data_type='string',
                    source='from_path_template'
                ))
            elif re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', part) and part not in ['api', 'v1', 'v2', 'rest']:
                if i > 0:
                    params.append(ParsedParameter(
                        name=part,
                        param_type='path',
                        data_type='string',
                        source='from_path_guess'
                    ))
        
        param_names = re.findall(r'(?:param|params|parameter|query|data|body|payload)\s*[:=]\s*\{[^}]*\}', content)
        for param in param_names[:5]:
            name_match = re.search(r'["\']?(\w+)["\']?\s*:', param)
            if name_match:
                params.append(ParsedParameter(
                    name=name_match.group(1),
                    param_type='body',
                    data_type='object',
                    source='from_code'
                ))
        
        return params
    
    def analyze_response(self, endpoint: SmartEndpoint, response_text: str) -> List[ParsedParameter]:
        """从响应中提取参数"""
        params = []
        
        matches = re.findall(r'"(\w+)":\s*(?:\{|\[|"[^"]*"|\d+|true|false|null)', response_text)
        for match in matches:
            if match not in ['id', 'code', 'msg', 'data', 'list', 'total', 'page', 'pages', 'size']:
                params.append(ParsedParameter(
                    name=match,
                    param_type='response',
                    data_type='mixed',
                    source='from_response'
                ))
        
        return params
    
    def extract_sensitive_data(self, content: str, source: str = "") -> List[SensitiveMatch]:
        """提取敏感信息"""
        matches = []
        
        patterns = {
            'AWS Access Key': (r'AKIA[0-9A-Z]{16}', Sensitivity.CRITICAL),
            'AWS Secret Key': (r'[A-Za-z0-9/+=]{40}', Sensitivity.CRITICAL),
            'JWT Token': (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', Sensitivity.HIGH),
            'Bearer Token': (r'Bearer\s+[A-Za-z0-9_-]+', Sensitivity.HIGH),
            'Basic Auth': (r'Basic\s+[A-Za-z0-9_-]+', Sensitivity.MEDIUM),
            'API Key': (r'[a-zA-Z0-9]{32,}', Sensitivity.MEDIUM),
            'Private Key': (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', Sensitivity.CRITICAL),
            'Password': (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', Sensitivity.HIGH),
            'Email': (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', Sensitivity.LOW),
            'Phone': (r'1[3-9]\d{9}', Sensitivity.LOW),
            'ID Card': (r'\d{17}[\dXx]', Sensitivity.CRITICAL),
        }
        
        for name, (pattern, severity) in patterns.items():
            regex_matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in regex_matches:
                value = match.group(0)
                if len(value) > 5 and len(value) < 500:
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    context = content[start:end]
                    
                    matches.append(SensitiveMatch(
                        data_type=name,
                        value=value[:50],
                        severity=severity,
                        context=context,
                        source=source
                    ))
        
        return matches
    
    def classify_endpoints(self) -> Dict[str, List[SmartEndpoint]]:
        """分类端点"""
        classified = {
            'auth': [],
            'admin': [],
            'user_data': [],
            'api': [],
            'other': [],
            'frontend': []
        }
        
        for ep in self.endpoints:
            if ep.is_auth_endpoint:
                classified['auth'].append(ep)
            elif ep.is_admin_endpoint:
                classified['admin'].append(ep)
            elif ep.is_user_data_endpoint:
                classified['user_data'].append(ep)
            elif ep.endpoint_type == EndpointType.BACKEND_API:
                classified['api'].append(ep)
            elif ep.endpoint_type == EndpointType.FRONTEND_ROUTE:
                classified['frontend'].append(ep)
            else:
                classified['other'].append(ep)
        
        return classified
    
    def generate_fuzz_targets(self) -> List[Tuple[str, str, Dict]]:
        """
        生成精准 fuzzing 目标
        
        返回: [(url, method, fuzz_params), ...]
        """
        targets = []
        
        classified = self.classify_endpoints()
        
        priority_order = ['auth', 'admin', 'user_data', 'api']
        
        for category in priority_order:
            for ep in classified[category]:
                full_url = ep.base_url + ep.path if ep.path.startswith('/') else ep.path
                
                params = {}
                for param in ep.parameters:
                    if param.param_type == 'path':
                        params[param.name] = self._get_fuzz_value(param.name)
                    elif param.param_type == 'query':
                        params[param.name] = self._get_fuzz_value(param.name)
                
                targets.append((full_url, ep.method, params))
        
        return targets
    
    def _get_fuzz_value(self, param_name: str) -> str:
        """根据参数名生成 fuzz 值"""
        fuzz_db = {
            'id': ["1", "0", "999999", "1 OR 1=1", "${jndi}"],
            'userId': ["1", "0", "admin", "1' OR '1'='1"],
            'page': ["1", "0", "999"],
            'pageSize': ["10", "100", "9999"],
            'search': ["' OR '1'='1", "<script>alert(1)</script>", "${jndi:ldap://}"],
            'q': ["' OR '1'='1", "<script>alert(1)</script>"],
            'query': ["' OR '1'='1", "<script>alert(1)</script>"],
            'type': ["1", "admin", "test"],
            'name': ["admin", "test", "' OR '1'='1"],
            'email': ["admin@test.com", "' OR '1'='1"],
            'password': ["admin", "123456", "' OR '1'='1"],
        }
        
        return fuzz_db.get(param_name.lower(), ["test", "1", "admin"])
    
    def get_high_value_targets(self) -> List[SmartEndpoint]:
        """获取高价值目标"""
        return [ep for ep in self.endpoints 
                if ep.sensitivity in [Sensitivity.CRITICAL, Sensitivity.HIGH]
                or ep.is_auth_endpoint or ep.is_admin_endpoint]


def smart_analyze(target_url: str, session: requests.Session = None) -> Dict:
    """
    智能分析主函数
    
    像渗透测试工程师一样：
    1. 收集 JS 文件
    2. 智能提取 API 端点
    3. 分类和评估
    4. 提取敏感信息
    5. 生成精准 fuzzing 目标
    """
    session = session or requests.Session()
    analyzer = SmartAPIAnalyzer(session)
    
    print("[*] Fetching target...")
    resp = session.get(target_url, timeout=10)
    html = resp.text
    
    js_url_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
    js_urls = re.findall(js_url_pattern, html)
    
    print(f"[*] Found {len(js_urls)} JS files")
    
    all_endpoints = []
    
    for js_url in js_urls[:5]:
        if not js_url.startswith('http'):
            js_url = urljoin(target_url, js_url)
        
        print(f"[*] Analyzing: {js_url.split('/')[-1]}")
        
        try:
            js_resp = session.get(js_url, timeout=10)
            content = js_resp.text
            
            endpoints = analyzer.analyze_js_file(js_url, content)
            all_endpoints.extend(endpoints)
            
            sensitive = analyzer.extract_sensitive_data(content, js_url)
            analyzer.sensitive_data.extend(sensitive)
            
        except Exception as e:
            print(f"[!] Error analyzing {js_url}: {e}")
    
    analyzer.endpoints = all_endpoints
    
    classified = analyzer.classify_endpoints()
    high_value = analyzer.get_high_value_targets()
    fuzz_targets = analyzer.generate_fuzz_targets()
    
    print(f"\n[*] Analysis Results:")
    print(f"    Total endpoints: {len(all_endpoints)}")
    print(f"    Auth endpoints: {len(classified['auth'])}")
    print(f"    Admin endpoints: {len(classified['admin'])}")
    print(f"    User data endpoints: {len(classified['user_data'])}")
    print(f"    API endpoints: {len(classified['api'])}")
    print(f"    High value targets: {len(high_value)}")
    print(f"    Fuzz targets: {len(fuzz_targets)}")
    print(f"    Sensitive data found: {len(analyzer.sensitive_data)}")
    
    return {
        'endpoints': all_endpoints,
        'classified': classified,
        'high_value': high_value,
        'fuzz_targets': fuzz_targets,
        'sensitive_data': analyzer.sensitive_data,
        'base_urls': list(analyzer.base_urls),
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.65.100.160:6004"
    result = smart_analyze(target)
