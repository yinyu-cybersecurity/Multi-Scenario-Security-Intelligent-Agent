#!/usr/bin/env python3
"""
Response Classifier - 响应综合分类器
多维度判断响应类型，像渗透测试工程师一样思考
"""

import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import requests


class ResponseType(Enum):
    """响应类型"""
    REAL_API_DOC = "real_api_doc"           # 真正的 API 文档
    SPA_FALLBACK = "spa_fallback"           # Vue.js/React SPA  fallback
    STATIC_RESOURCE = "static_resource"     # 静态资源
    REST_API_ENDPOINT = "rest_api_endpoint"  # REST API 端点
    GRAPHQL_ENDPOINT = "graphql_endpoint"    # GraphQL 端点
    ERROR_PAGE = "error_page"               # 错误页面
    LOGIN_PAGE = "login_page"               # 登录页面
    ADMIN_PAGE = "admin_page"                # 管理后台
    UNKNOWN = "unknown"


class Confidence(Enum):
    """置信度"""
    HIGH = "high"      # >= 90%
    MEDIUM = "medium"  # >= 70%
    LOW = "low"        # >= 50%
    UNCERTAIN = "uncertain"


@dataclass
class ResponseAnalysis:
    """响应分析结果"""
    url: str
    response_type: ResponseType
    confidence: Confidence
    
    # 原始数据
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    content_hash: str = ""
    
    # 特征检测
    is_json: bool = False
    is_yaml: bool = False
    is_html: bool = False
    is_xml: bool = False
    
    # 内容特征
    has_swagger: bool = False
    has_openapi: bool = False
    has_paths: bool = False
    has_api_paths: bool = False
    has_api_keyword: bool = False
    has_login_form: bool = False
    has_admin_keyword: bool = False
    has_error_keyword: bool = False
    has_graphql_keyword: bool = False
    has_websocket_keyword: bool = False
    
    # JSON 特定
    json_structure: Dict = None
    json_endpoints: List = None
    json_has_servers: bool = False
    json_has_components: bool = False
    
    # 其他
    content_preview: str = ""
    reasoning: str = ""
    
    def __post_init__(self):
        if self.json_structure is None:
            self.json_structure = {}
        if self.json_endpoints is None:
            self.json_endpoints = []


class ResponseClassifier:
    """
    响应综合分类器
    
    核心思维：不像新手只靠状态码判断，而是综合分析：
    1. Content-Type 头
    2. 响应内容本身
    3. JSON 结构特征
    4. 特定关键字
    5. 响应大小
    """
    
    # 登录页面特征
    LOGIN_PATTERNS = [
        r'<form[^>]*login',
        r'<input[^>]*name=["\']username',
        r'<input[^>]*name=["\']password',
        r'login.*username',
        r'username.*password',
        r'doLogin',
        r'loginForm',
        r'signin',
        r'登录',
        r'用户名',
        r'密码',
    ]
    
    # 管理后台特征
    ADMIN_PATTERNS = [
        r'admin.*panel',
        r'dashboard',
        r'control.*panel',
        r'management',
        r'后台管理',
        r'管理员',
    ]
    
    # 错误页面特征
    ERROR_PATTERNS = [
        r'404.*not.*found',
        r'500.*error',
        r'403.*forbidden',
        r'access.*denied',
        r'unauthorized',
        r'error.*occurred',
        r'页面不存在',
        r'访问被拒绝',
    ]
    
    # GraphQL 特征
    GRAPHQL_PATTERNS = [
        r'__schema',
        r'__type',
        r'graphiql',
        r'graphql',
        r'application/graphql',
    ]
    
    # Swagger/OpenAPI 特征
    SWAGGER_PATTERNS = [
        r'"swagger"',
        r'"openapi"',
        r'"paths"',
        r'"info"',
        r'"components"',
        r'"schemas"',
        r'"security"',
    ]
    
    # REST API 特征
    REST_PATTERNS = [
        r'/api/v',
        r'/rest/',
        r'"method"',
        r'"endpoint"',
        r'"route"',
        r'"status"',
        r'"message"',
        r'"code"',
        r'"data"',
        r'"result"',
    ]
    
    # API 相关关键字
    API_KEYWORDS = [
        'api', 'endpoint', 'route', 'resource', 'collection',
        'user', 'product', 'order', 'admin', 'auth', 'login',
        'get', 'post', 'put', 'delete', 'patch',
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.baseline_hash = ""
        self.baseline_length = 0
    
    def analyze(self, url: str, response: requests.Response = None) -> ResponseAnalysis:
        """
        综合分析响应
        
        Args:
            url: 请求的 URL
            response: requests.Response 对象
        
        Returns:
            ResponseAnalysis 对象
        """
        if response is None:
            response = self.session.get(url, timeout=10, allow_redirects=True)
        
        analysis = ResponseAnalysis(
            url=url,
            response_type=ResponseType.UNKNOWN,
            confidence=Confidence.UNCERTAIN,
            status_code=response.status_code,
            content_type=response.headers.get('Content-Type', ''),
            content_length=len(response.content),
            content_hash=hashlib.md5(response.content).hexdigest(),
            content_preview=response.text[:200]
        )
        
        content = response.text
        content_lower = content.lower()
        
        # 1. 检测内容类型
        analysis.is_json = self._is_json(content)
        analysis.is_yaml = self._is_yaml(content)
        analysis.is_html = self._is_html(content)
        analysis.is_xml = self._is_xml(content)
        
        # 2. JSON 特定分析
        if analysis.is_json:
            analysis.json_structure = self._parse_json(content)
            if analysis.json_structure:
                analysis.json_has_servers = 'servers' in analysis.json_structure
                analysis.json_has_components = 'components' in analysis.json_structure
                
                # 检测 Swagger/OpenAPI
                if any(p.replace('"', '') in content for p in self.SWAGGER_PATTERNS):
                    analysis.has_swagger = True
                    if '"openapi"' in content or "'openapi'" in content:
                        analysis.has_openapi = True
                
                # 提取端点
                analysis.json_endpoints = self._extract_json_endpoints(analysis.json_structure)
        
        # 3. HTML 特定分析
        if analysis.is_html:
            analysis.has_login_form = self._match_patterns(content, self.LOGIN_PATTERNS)
            analysis.has_admin_keyword = self._match_patterns(content, self.ADMIN_PATTERNS)
            analysis.has_error_keyword = self._match_patterns(content, self.ERROR_PATTERNS)
        
        # 4. 通用内容分析
        analysis.has_api_paths = bool(re.search(r'/api/v\d+', content))
        analysis.has_api_keyword = any(kw in content_lower for kw in self.API_KEYWORDS)
        analysis.has_graphql_keyword = self._match_patterns(content, self.GRAPHQL_PATTERNS)
        
        # 5. 分类判断
        analysis.response_type, analysis.confidence, analysis.reasoning = self._classify(analysis)
        
        return analysis
    
    def _is_json(self, content: str) -> bool:
        """检测是否为 JSON"""
        if not content or not content.strip():
            return False
        
        content = content.strip()
        
        if content.startswith('{') or content.startswith('['):
            try:
                json.loads(content)
                return True
            except:
                pass
        
        return False
    
    def _is_yaml(self, content: str) -> bool:
        """检测是否为 YAML"""
        if not content:
            return False
        
        yaml_indicators = ['---', 'openapi:', 'swagger:', 'paths:', 'components:']
        return any(indicator in content for indicator in yaml_indicators)
    
    def _is_html(self, content: str) -> bool:
        """检测是否为 HTML"""
        html_indicators = ['<!doctype', '<html', '<head>', '<body>', '<div']
        return any(indicator in content[:200].lower() for indicator in html_indicators)
    
    def _is_xml(self, content: str) -> bool:
        """检测是否为 XML"""
        return content.strip().startswith('<?xml') or content.strip().startswith('<')
    
    def _parse_json(self, content: str) -> Dict:
        """解析 JSON"""
        try:
            return json.loads(content)
        except:
            return {}
    
    def _extract_json_endpoints(self, data: Dict) -> List[str]:
        """从 JSON 中提取端点"""
        endpoints = []
        
        if 'paths' in data:
            for path in data['paths'].keys():
                endpoints.append(path)
        
        if 'servers' in data:
            for server in data['servers']:
                if isinstance(server, dict) and 'url' in server:
                    endpoints.append(f"server: {server['url']}")
        
        return endpoints
    
    def _match_patterns(self, content: str, patterns: List[str]) -> bool:
        """检测是否匹配模式"""
        content_lower = content.lower()
        for pattern in patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        return False
    
    def _classify(self, analysis: ResponseAnalysis) -> Tuple[ResponseType, Confidence, str]:
        """
        综合判断响应类型
        
        Returns:
            (ResponseType, Confidence, reasoning)
        """
        # === 1. 真正的 API 文档 (最高优先级) ===
        if analysis.is_json and analysis.has_swagger:
            if analysis.json_endpoints:
                return (
                    ResponseType.REAL_API_DOC,
                    Confidence.HIGH,
                    f"JSON with Swagger/OpenAPI, {len(analysis.json_endpoints)} endpoints found"
                )
            return (
                ResponseType.REAL_API_DOC,
                Confidence.MEDIUM,
                "JSON with Swagger/OpenAPI structure"
            )
        
        # === 2. GraphQL 端点 ===
        if analysis.has_graphql_keyword and analysis.is_json:
            return (
                ResponseType.GRAPHQL_ENDPOINT,
                Confidence.HIGH,
                "GraphQL __schema or __type found"
            )
        
        # === 3. REST API 端点 ===
        if analysis.is_json:
            rest_score = 0
            if analysis.has_api_paths:
                rest_score += 3
            if analysis.has_api_keyword:
                rest_score += 2
            if analysis.json_has_servers:
                rest_score += 3
            if analysis.json_endpoints:
                rest_score += 2
            
            if rest_score >= 4:
                return (
                    ResponseType.REST_API_ENDPOINT,
                    Confidence.HIGH if rest_score >= 6 else Confidence.MEDIUM,
                    f"JSON REST API structure (score: {rest_score})"
                )
        
        # === 4. 登录页面 ===
        if analysis.is_html and analysis.has_login_form:
            return (
                ResponseType.LOGIN_PAGE,
                Confidence.HIGH,
                "HTML login form detected"
            )
        
        # === 5. 管理后台 ===
        if analysis.is_html and analysis.has_admin_keyword:
            return (
                ResponseType.ADMIN_PAGE,
                Confidence.MEDIUM,
                "Admin dashboard keywords found"
            )
        
        # === 6. 错误页面 ===
        if analysis.status_code >= 400:
            if analysis.is_html and analysis.has_error_keyword:
                return (
                    ResponseType.ERROR_PAGE,
                    Confidence.HIGH,
                    f"Error page ({analysis.status_code})"
                )
        
        # === 7. Vue.js/React SPA Fallback ===
        if analysis.is_html:
            # Vue SPA 典型特征
            if any(x in analysis.content_preview for x in ['chunk-vendors', '__VUE__', 'vue', 'react']):
                return (
                    ResponseType.SPA_FALLBACK,
                    Confidence.HIGH,
                    "Vue.js/React SPA fallback detected"
                )
            
            # React SPA 特征
            if '__NEXT_DATA__' in analysis.content_preview or '_NEXT' in analysis.content_preview:
                return (
                    ResponseType.SPA_FALLBACK,
                    Confidence.HIGH,
                    "Next.js SPA fallback detected"
                )
            
            # Angular SPA 特征
            if 'ng-version' in analysis.content_preview or 'angular' in analysis.content_preview:
                return (
                    ResponseType.SPA_FALLBACK,
                    Confidence.HIGH,
                    "Angular SPA fallback detected"
                )
            
            # 通用 SPA 特征
            if '<div id="app">' in analysis.content_preview or '<div id="root">' in analysis.content_preview:
                return (
                    ResponseType.SPA_FALLBACK,
                    Confidence.HIGH,
                    "SPA div#app or div#root detected"
                )
            
            return (
                ResponseType.SPA_FALLBACK,
                Confidence.MEDIUM,
                "HTML content (likely SPA)"
            )
        
        # === 8. 静态资源 ===
        static_extensions = ['.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2']
        if any(analysis.url.endswith(ext) for ext in static_extensions):
            return (
                ResponseType.STATIC_RESOURCE,
                Confidence.HIGH,
                "Static resource file"
            )
        
        # === 9. 未知 ===
        return (
            ResponseType.UNKNOWN,
            Confidence.UNCERTAIN,
            f"Cannot determine (status={analysis.status_code}, type={analysis.content_type})"
        )
    
    def set_baseline(self, url: str):
        """设置基线响应用于对比"""
        try:
            resp = self.session.get(url, timeout=10)
            self.baseline_hash = hashlib.md5(resp.content).hexdigest()
            self.baseline_length = len(resp.content)
        except:
            pass
    
    def is_different_from_baseline(self, resp: requests.Response) -> bool:
        """判断响应是否与基线不同"""
        if not self.baseline_hash:
            return True
        
        content_hash = hashlib.md5(resp.content).hexdigest()
        return content_hash != self.baseline_hash
    
    def classify_batch(self, urls: List[str]) -> List[ResponseAnalysis]:
        """批量分类"""
        results = []
        for url in urls:
            try:
                analysis = self.analyze(url)
                results.append(analysis)
            except Exception as e:
                results.append(ResponseAnalysis(
                    url=url,
                    response_type=ResponseType.UNKNOWN,
                    confidence=Confidence.UNCERTAIN,
                    reasoning=f"Error: {str(e)}"
                ))
        return results


def smart_discover_and_classify(target_url: str, session: requests.Session = None) -> Dict:
    """
    智能发现并分类 API 端点
    
    像渗透测试工程师一样：
    1. 多维度判断响应类型
    2. 识别 SPA fallback
    3. 发现真正的 API 端点
    """
    session = session or requests.Session()
    classifier = ResponseClassifier(session)
    
    print("[*] Starting smart discovery and classification...")
    
    # 从 JS 提取父路径
    from smart_analyzer import SmartAPIAnalyzer
    analyzer = SmartAPIAnalyzer(session)
    
    resp = session.get(target_url, timeout=10)
    js_url_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
    js_urls = re.findall(js_url_pattern, resp.text)
    
    parent_paths = set()
    for js_url in js_urls[:5]:
        if not js_url.startswith('http'):
            js_url = target_url.rstrip('/') + '/' + js_url
        
        try:
            js_resp = session.get(js_url, timeout=10)
            endpoints = analyzer.analyze_js_file(js_url, js_resp.text)
            
            for ep in endpoints:
                parts = ep.path.strip('/').split('/')
                for i in range(1, len(parts)):
                    parent_paths.add('/' + '/'.join(parts[:i]))
        except:
            pass
    
    print(f"[*] Found {len(parent_paths)} parent paths")
    
    # 分类测试
    swagger_suffixes = [
        '/swagger.json', '/v3/api-docs', '/v2/api-docs',
        '/api-docs', '/openapi.json', '/swagger.yaml',
    ]
    
    classified = {
        'real_api_docs': [],
        'rest_endpoints': [],
        'spa_fallbacks': [],
        'login_pages': [],
        'admin_pages': [],
        'unknowns': [],
    }
    
    for parent in list(parent_paths)[:15]:
        for suffix in swagger_suffixes:
            url = target_url.rstrip('/') + parent + suffix
            
            try:
                resp = session.get(url, timeout=5, allow_redirects=True)
                analysis = classifier.analyze(url, resp)
                
                if analysis.response_type == ResponseType.REAL_API_DOC:
                    classified['real_api_docs'].append({
                        'url': url,
                        'endpoints': analysis.json_endpoints,
                        'confidence': analysis.confidence.value
                    })
                elif analysis.response_type == ResponseType.REST_API_ENDPOINT:
                    classified['rest_endpoints'].append({
                        'url': url,
                        'confidence': analysis.confidence.value
                    })
                elif analysis.response_type == ResponseType.SPA_FALLBACK:
                    classified['spa_fallbacks'].append({
                        'url': url,
                        'reasoning': analysis.reasoning
                    })
                elif analysis.response_type == ResponseType.LOGIN_PAGE:
                    classified['login_pages'].append(url)
                elif analysis.response_type == ResponseType.ADMIN_PAGE:
                    classified['admin_pages'].append(url)
                else:
                    classified['unknowns'].append({
                        'url': url,
                        'reasoning': analysis.reasoning
                    })
                    
            except Exception as e:
                classified['unknowns'].append({
                    'url': url,
                    'reasoning': f"Request error: {e}"
                })
    
    return {
        'target': target_url,
        'parent_paths_count': len(parent_paths),
        'classified': classified,
        'summary': {
            'real_api_docs': len(classified['real_api_docs']),
            'rest_endpoints': len(classified['rest_endpoints']),
            'spa_fallbacks': len(classified['spa_fallbacks']),
            'login_pages': len(classified['login_pages']),
            'admin_pages': len(classified['admin_pages']),
        }
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://49.65.100.160:6004"
    
    result = smart_discover_and_classify(target)
    
    print("\n" + "=" * 70)
    print(" Smart Discovery & Classification Results")
    print("=" * 70)
    
    print(f"\n[*] Target: {result['target']}")
    print(f"[*] Parent paths tested: {result['parent_paths_count']}")
    
    summary = result['summary']
    print(f"\n[*] Summary:")
    print(f"    Real API Docs: {summary['real_api_docs']}")
    print(f"    REST Endpoints: {summary['rest_endpoints']}")
    print(f"    SPA Fallbacks: {summary['spa_fallbacks']}")
    print(f"    Login Pages: {summary['login_pages']}")
    print(f"    Admin Pages: {summary['admin_pages']}")
    
    if result['classified']['real_api_docs']:
        print(f"\n[*] Real API Docs Found:")
        for doc in result['classified']['real_api_docs'][:5]:
            print(f"    - {doc['url']}")
            print(f"      Endpoints: {doc['endpoints'][:5] if doc['endpoints'] else 'N/A'}")
