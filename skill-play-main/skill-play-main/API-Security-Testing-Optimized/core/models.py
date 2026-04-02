#!/usr/bin/env python3
"""
Data Models - 数据模型
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """漏洞严重等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EndpointSource(Enum):
    """端点来源"""
    JS_PARSER = "js_parser"
    AST_ANALYZER = "ast_analyzer"
    FUZZ_API = "fuzz_api"
    SWAGGER = "swagger"
    BROWSER = "browser"
    MANUAL = "manual"


@dataclass
class APIEndpoint:
    """
    API 端点模型
    
    属性:
    - path: API 路径
    - method: HTTP 方法
    - parameters: 参数集合
    - source: 端点来源
    - full_url: 完整 URL
    - score: 评分
    - is_high_value: 是否高价值目标
    - status_code: HTTP 状态码
    - content_length: 响应内容长度
    """
    path: str
    method: str = "GET"
    parameters: Set[str] = field(default_factory=set)
    source: str = "unknown"
    full_url: str = ""
    score: int = 0
    is_high_value: bool = False
    status_code: int = 0
    content_length: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'method': self.method,
            'parameters': list(self.parameters),
            'source': self.source,
            'full_url': self.full_url,
            'score': self.score,
            'is_high_value': self.is_high_value,
            'status_code': self.status_code,
            'content_length': self.content_length,
            'tags': list(self.tags)
        }
    
    @property
    def endpoint_id(self) -> str:
        """端点唯一标识"""
        return f"{self.method}:{self.path}"


@dataclass
class Vulnerability:
    """
    漏洞模型
    
    属性:
    - vuln_type: 漏洞类型
    - severity: 严重等级
    - endpoint: 关联端点
    - method: HTTP 方法
    - payload: 攻击载荷
    - evidence: 证据
    """
    vuln_type: str
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    method: str = "GET"
    payload: str = ""
    evidence: str = ""
    status_code: int = 0
    req_headers: Dict[str, str] = field(default_factory=dict)
    resp_headers: Dict[str, str] = field(default_factory=dict)
    resp_content: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict:
        return {
            'type': self.vuln_type,
            'severity': self.severity.value,
            'endpoint': self.endpoint,
            'method': self.method,
            'payload': self.payload,
            'evidence': self.evidence,
            'status_code': self.status_code,
            'timestamp': self.timestamp
        }


@dataclass
class SensitiveData:
    """
    敏感信息模型
    """
    data_type: str
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    value: str = ""
    matched_pattern: str = ""
    context: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'data_type': self.data_type,
            'severity': self.severity.value,
            'endpoint': self.endpoint,
            'value': self.value[:50] + "..." if len(self.value) > 50 else self.value,
            'matched_pattern': self.matched_pattern
        }


@dataclass
class ScanResult:
    """
    扫描结果模型
    
    属性:
    - target_url: 目标 URL
    - start_time: 开始时间
    - end_time: 结束时间
    - status: 扫描状态
    - total_apis: 总 API 数
    - alive_apis: 存活 API 数
    - high_value_apis: 高价值 API 数
    - api_endpoints: API 端点列表
    - vulnerabilities: 漏洞列表
    - sensitive_data: 敏感信息列表
    - collector_data: 采集阶段数据
    - errors: 错误列表
    """
    target_url: str
    start_time: str = ""
    end_time: str = ""
    status: str = "pending"
    total_apis: int = 0
    alive_apis: int = 0
    high_value_apis: int = 0
    api_endpoints: List[APIEndpoint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    sensitive_data: List[SensitiveData] = field(default_factory=list)
    collector_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'target_url': self.target_url,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'status': self.status,
            'summary': {
                'total_apis': self.total_apis,
                'alive_apis': self.alive_apis,
                'high_value_apis': self.high_value_apis,
                'vulnerabilities': {
                    'critical': len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL]),
                    'high': len([v for v in self.vulnerabilities if v.severity == Severity.HIGH]),
                    'medium': len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM]),
                    'low': len([v for v in self.vulnerabilities if v.severity == Severity.LOW]),
                },
                'sensitive_data': len(self.sensitive_data)
            },
            'api_endpoints': [ep.to_dict() for ep in self.api_endpoints],
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'sensitive_data': [s.to_dict() for s in self.sensitive_data],
            'errors': self.errors
        }
    
    def add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞"""
        self.vulnerabilities.append(vuln)
    
    def add_endpoint(self, endpoint: APIEndpoint):
        """添加端点"""
        self.api_endpoints.append(endpoint)
    
    @property
    def vuln_count_by_severity(self) -> Dict[str, int]:
        """按严重等级统计漏洞"""
        return {
            'critical': len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL]),
            'high': len([v for v in self.vulnerabilities if v.severity == Severity.HIGH]),
            'medium': len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM]),
            'low': len([v for v in self.vulnerabilities if v.severity == Severity.LOW]),
        }
    
    @property
    def total_vulnerabilities(self) -> int:
        """漏洞总数"""
        return len(self.vulnerabilities)


@dataclass
class JSFile:
    """
    JS 文件模型
    """
    url: str
    content_hash: str = ""
    content: str = ""
    endpoints: List[Dict] = field(default_factory=list)
    parameter_names: Set[str] = field(default_factory=set)
    routes: List[str] = field(default_factory=list)
    env_configs: Dict[str, str] = field(default_factory=dict)
    is_alive: bool = False
    size: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'content_hash': self.content_hash,
            'endpoints': self.endpoints,
            'parameters': list(self.parameter_names),
            'routes': self.routes,
            'env_configs': self.env_configs,
            'is_alive': self.is_alive,
            'size': self.size
        }


@dataclass
class APIFindResult:
    """
    API 发现结果
    """
    path: str
    method: str = "GET"
    source_type: str = ""
    url_type: str = ""
    parameters: Set[str] = field(default_factory=set)
    confidence: float = 1.0
    
    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'method': self.method,
            'source_type': self.source_type,
            'url_type': self.url_type,
            'parameters': list(self.parameters),
            'confidence': self.confidence
        }


@dataclass
class ProxyResult:
    """
    代理扫描结果
    """
    method: str
    url: str
    path: str
    headers: Dict[str, str]
    body: str = ""
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict:
        return {
            'method': self.method,
            'url': self.url,
            'path': self.path,
            'headers': self.headers,
            'body': self.body[:500] if self.body else '',
            'status_code': self.status_code,
            'response_headers': self.response_headers,
            'response_body': self.response_body[:500] if self.response_body else '',
            'timestamp': self.timestamp
        }
