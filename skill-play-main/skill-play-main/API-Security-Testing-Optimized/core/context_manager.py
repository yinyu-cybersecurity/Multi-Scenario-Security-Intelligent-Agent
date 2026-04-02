#!/usr/bin/env python3
"""
Context Manager - 上下文管理器

维护和管理全维度上下文：
- TechStackContext: 技术栈上下文
- NetworkContext: 网络环境上下文
- SecurityContext: 安全态势上下文
- ContentContext: 内容特征上下文
- GlobalContext: 全局上下文
"""

import json
import pickle
import hashlib
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class RateLimitStatus(Enum):
    """速率限制状态"""
    NORMAL = "normal"
    WARNING = "warning"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"


class ExposureLevel(Enum):
    """暴露等级"""
    INTERNAL = "internal"
    PARTNER = "partner"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class DataClassification(Enum):
    """数据分类"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class TestPhase(Enum):
    """测试阶段"""
    INIT = "init"
    RECON = "recon"
    DISCOVERY = "discovery"
    CLASSIFICATION = "classification"
    FUZZING = "fuzzing"
    TESTING = "testing"
    REPORT = "report"


@dataclass
class ProxyConfig:
    """代理配置"""
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    no_proxy: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'http_proxy': self.http_proxy,
            'https_proxy': self.https_proxy,
            'no_proxy': self.no_proxy
        }


@dataclass
class TechStackContext:
    """技术栈上下文"""
    frontend: Set[str] = field(default_factory=set)
    backend: Set[str] = field(default_factory=set)
    database: Set[str] = field(default_factory=set)
    api_type: Set[str] = field(default_factory=set)
    waf: Optional[str] = None
    cdn: Optional[str] = None
    
    confidence: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'frontend': list(self.frontend),
            'backend': list(self.backend),
            'database': list(self.database),
            'api_type': list(self.api_type),
            'waf': self.waf,
            'cdn': self.cdn,
            'confidence': self.confidence
        }
    
    def is_empty(self) -> bool:
        return not (self.frontend or self.backend or self.database or self.api_type)
    
    def get_primary_stack(self) -> Optional[str]:
        if self.backend:
            return list(self.backend)[0]
        if self.frontend:
            return list(self.frontend)[0]
        return None


@dataclass
class NetworkContext:
    """网络环境上下文"""
    is_reachable: bool = True
    requires_proxy: bool = False
    proxy_config: Optional[ProxyConfig] = None
    rate_limit_status: RateLimitStatus = RateLimitStatus.NORMAL
    blocked_count: int = 0
    consecutive_failures: int = 0
    dns_resolution: Optional[str] = None
    
    last_request_time: Optional[datetime] = None
    last_failure_time: Optional[datetime] = None
    
    user_agents: List[str] = field(default_factory=list)
    current_user_agent: str = "Mozilla/5.0 (compatible; SecurityTesting/2.0)"
    
    def to_dict(self) -> Dict:
        return {
            'is_reachable': self.is_reachable,
            'requires_proxy': self.requires_proxy,
            'proxy_config': self.proxy_config.to_dict() if self.proxy_config else None,
            'rate_limit_status': self.rate_limit_status.value,
            'blocked_count': self.blocked_count,
            'consecutive_failures': self.consecutive_failures,
            'dns_resolution': self.dns_resolution,
            'current_user_agent': self.current_user_agent
        }


@dataclass
class SecurityContext:
    """安全态势上下文"""
    auth_required: bool = False
    auth_type: Optional[str] = None
    auth_endpoints: Set[str] = field(default_factory=set)
    sensitive_endpoints: Set[str] = field(default_factory=set)
    exposure_level: ExposureLevel = ExposureLevel.UNKNOWN
    data_classification: DataClassification = DataClassification.INTERNAL
    
    session_tokens: List[str] = field(default_factory=list)
    jwt_algorithms: List[str] = field(default_factory=list)
    api_keys: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'auth_required': self.auth_required,
            'auth_type': self.auth_type,
            'auth_endpoints': list(self.auth_endpoints),
            'sensitive_endpoints': list(self.sensitive_endpoints),
            'exposure_level': self.exposure_level.value,
            'data_classification': self.data_classification.value
        }
    
    def is_sensitive_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        sensitive_patterns = ['/admin', '/login', '/password', '/pay', '/order', 
                             '/checkout', '/transfer', '/delete', '/config']
        return any(pattern in url_lower for pattern in sensitive_patterns)


@dataclass
class ContentContext:
    """内容特征上下文"""
    is_spa: bool = False
    has_api_docs: bool = False
    swagger_urls: List[str] = field(default_factory=list)
    error_leaks: List[str] = field(default_factory=list)
    base_urls: Set[str] = field(default_factory=set)
    internal_ips: Set[str] = field(default_factory=set)
    
    response_pattern: str = "normal"
    spa_fallback_size: Optional[int] = None
    
    js_urls: List[str] = field(default_factory=list)
    api_paths: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'is_spa': self.is_spa,
            'has_api_docs': self.has_api_docs,
            'swagger_urls': self.swagger_urls,
            'error_leaks': self.error_leaks,
            'base_urls': list(self.base_urls),
            'internal_ips': list(self.internal_ips),
            'response_pattern': self.response_pattern,
            'spa_fallback_size': self.spa_fallback_size
        }


@dataclass
class Endpoint:
    """API 端点"""
    path: str
    method: str = "GET"
    score: int = 0
    is_high_value: bool = False
    is_alive: bool = False
    status_code: Optional[int] = None
    parameters: List[str] = field(default_factory=list)
    source: str = "unknown"
    
    def to_dict(self) -> Dict:
        return {
            'path': self.path,
            'method': self.method,
            'score': self.score,
            'is_high_value': self.is_high_value,
            'is_alive': self.is_alive,
            'status_code': self.status_code,
            'parameters': self.parameters,
            'source': self.source
        }


@dataclass
class TestRecord:
    """测试记录"""
    timestamp: datetime
    endpoint: str
    action: str
    payload: Optional[str] = None
    result: str = ""
    response_time: float = 0.0
    status_code: Optional[int] = None
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'endpoint': self.endpoint,
            'action': self.action,
            'payload': self.payload,
            'result': self.result,
            'response_time': self.response_time,
            'status_code': self.status_code
        }


@dataclass
class GlobalContext:
    """全局上下文"""
    target_url: str
    start_time: datetime
    current_phase: TestPhase = TestPhase.INIT
    
    tech_stack: TechStackContext = field(default_factory=TechStackContext)
    network: NetworkContext = field(default_factory=NetworkContext)
    security: SecurityContext = field(default_factory=SecurityContext)
    content: ContentContext = field(default_factory=ContentContext)
    
    discovered_endpoints: List[Endpoint] = field(default_factory=list)
    test_history: List[TestRecord] = field(default_factory=list)
    
    user_preferences: Dict[str, Any] = field(default_factory=dict)
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'target_url': self.target_url,
            'start_time': self.start_time.isoformat(),
            'current_phase': self.current_phase.value,
            'tech_stack': self.tech_stack.to_dict(),
            'network': self.network.to_dict(),
            'security': self.security.to_dict(),
            'content': self.content.to_dict(),
            'discovered_endpoints': [e.to_dict() for e in self.discovered_endpoints],
            'test_history': [t.to_dict() for t in self.test_history],
            'user_preferences': self.user_preferences,
            'metadata': self.metadata
        }


class ContextManager:
    """
    上下文管理器
    
    职责：
    - 维护和管理全局上下文
    - 提供上下文更新接口
    - 支持上下文持久化和恢复
    - 触发上下文更新事件
    """
    
    def __init__(self, target_url: str):
        self.context = GlobalContext(
            target_url=target_url,
            start_time=datetime.now()
        )
        
        self.update_handlers: Dict[str, List[Callable]] = defaultdict(list)
        
        self._history: List[Dict] = []
    
    def on_update(self, key: str, handler: Callable):
        """注册上下文更新处理器"""
        self.update_handlers[key].append(handler)
    
    def _emit_update(self, key: str, old_value: Any, new_value: Any):
        """触发更新事件"""
        for handler in self.update_handlers.get(key, []):
            try:
                handler(old_value, new_value)
            except Exception as e:
                logger.warning(f"Update handler error ({key}): {e}")
    
    def update_tech_stack(self, fingerprints: Dict[str, Set[str]]):
        """更新技术栈上下文"""
        old_stack = asdict(self.context.tech_stack)
        
        for category, techs in fingerprints.items():
            if category == 'frontend':
                self.context.tech_stack.frontend.update(techs)
            elif category == 'backend':
                self.context.tech_stack.backend.update(techs)
            elif category == 'database':
                self.context.tech_stack.database.update(techs)
            elif category == 'api_type':
                self.context.tech_stack.api_type.update(techs)
        
        for tech in fingerprints.get('frontend', set()) | fingerprints.get('backend', set()):
            if tech not in self.context.tech_stack.confidence:
                self.context.tech_stack.confidence[tech] = 0.8
        
        self._emit_update('tech_stack', old_stack, asdict(self.context.tech_stack))
        self._record_change('tech_stack_update', fingerprints)
    
    def set_waf(self, waf_name: str, confidence: float = 0.8):
        """设置 WAF"""
        old_waf = self.context.tech_stack.waf
        self.context.tech_stack.waf = waf_name
        self.context.tech_stack.confidence['waf'] = confidence
        
        self._emit_update('waf', old_waf, waf_name)
    
    def set_cdn(self, cdn_name: str):
        """设置 CDN"""
        self.context.tech_stack.cdn = cdn_name
    
    def update_network_status(self, reachable: bool, reason: Optional[str] = None):
        """更新网络状态"""
        old_reachable = self.context.network.is_reachable
        self.context.network.is_reachable = reachable
        
        if not reachable:
            self.context.network.consecutive_failures += 1
            
            if self.context.network.consecutive_failures >= 3:
                self.context.network.rate_limit_status = RateLimitStatus.RATE_LIMITED
            if self.context.network.consecutive_failures >= 5:
                self.context.network.rate_limit_status = RateLimitStatus.BLOCKED
                self.context.network.blocked_count += 1
        else:
            self.context.network.consecutive_failures = 0
            self.context.network.rate_limit_status = RateLimitStatus.NORMAL
        
        self.context.network.last_request_time = datetime.now()
        
        self._emit_update('network_status', old_reachable, reachable)
        self._record_change('network_status', {'reachable': reachable, 'reason': reason})
    
    def set_proxy(self, proxy_config: ProxyConfig):
        """设置代理"""
        old_proxy = self.context.network.requires_proxy
        self.context.network.proxy_config = proxy_config
        self.context.network.requires_proxy = True
        
        self._emit_update('proxy', old_proxy, True)
    
    def mark_internal_address(self, address: str, source: str = "response"):
        """标记内网地址"""
        if address not in self.context.content.internal_ips:
            self.context.content.internal_ips.add(address)
            self._emit_update('internal_address', None, address)
            self._record_change('internal_address_found', {'address': address, 'source': source})
    
    def update_rate_limit(self, blocked: bool, increment: int = 1):
        """更新速率限制状态"""
        if blocked:
            self.context.network.blocked_count += increment
            self.context.network.rate_limit_status = RateLimitStatus.RATE_LIMITED
        else:
            self.context.network.rate_limit_status = RateLimitStatus.NORMAL
    
    def set_user_agent(self, user_agent: str):
        """设置 User-Agent"""
        old_ua = self.context.network.current_user_agent
        self.context.network.current_user_agent = user_agent
        
        if user_agent not in self.context.network.user_agents:
            self.context.network.user_agents.append(user_agent)
        
        self._emit_update('user_agent', old_ua, user_agent)
    
    def rotate_user_agent(self) -> str:
        """轮换 User-Agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
        ]
        
        current = self.context.network.current_user_agent
        for ua in user_agents:
            if ua != current:
                self.set_user_agent(ua)
                return ua
        
        return current
    
    def set_auth_required(self, required: bool, auth_type: Optional[str] = None):
        """设置认证要求"""
        self.context.security.auth_required = required
        if auth_type:
            self.context.security.auth_type = auth_type
    
    def add_auth_endpoint(self, endpoint: str):
        """添加认证端点"""
        self.context.security.auth_endpoints.add(endpoint)
    
    def add_sensitive_endpoint(self, endpoint: str):
        """添加敏感端点"""
        self.context.security.sensitive_endpoints.add(endpoint)
    
    def set_exposure_level(self, level: ExposureLevel):
        """设置暴露等级"""
        self.context.security.exposure_level = level
    
    def set_data_classification(self, classification: DataClassification):
        """设置数据分类"""
        self.context.security.data_classification = classification
    
    def set_spa_mode(self, is_spa: bool, fallback_size: Optional[int] = None):
        """设置 SPA 模式"""
        self.context.content.is_spa = is_spa
        if fallback_size:
            self.context.content.spa_fallback_size = fallback_size
    
    def add_swagger_url(self, url: str):
        """添加 Swagger URL"""
        if url not in self.context.content.swagger_urls:
            self.context.content.swagger_urls.append(url)
            self.context.content.has_api_docs = True
    
    def add_error_leak(self, error: str):
        """添加错误泄露"""
        if error not in self.context.content.error_leaks:
            self.context.content.error_leaks.append(error)
    
    def add_base_url(self, url: str):
        """添加 Base URL"""
        self.context.content.base_urls.add(url)
    
    def add_js_url(self, url: str):
        """添加 JS URL"""
        if url not in self.context.content.js_urls:
            self.context.content.js_urls.append(url)
    
    def add_api_path(self, path: str):
        """添加 API 路径"""
        if path not in self.context.content.api_paths:
            self.context.content.api_paths.append(path)
    
    def add_discovered_endpoint(self, endpoint: Endpoint):
        """添加发现的端点"""
        for existing in self.context.discovered_endpoints:
            if existing.path == endpoint.path and existing.method == endpoint.method:
                return
        
        self.context.discovered_endpoints.append(endpoint)
        self._emit_update('endpoint_discovered', None, endpoint.to_dict())
    
    def update_endpoint_status(self, path: str, method: str, is_alive: bool, status_code: Optional[int] = None):
        """更新端点状态"""
        for endpoint in self.context.discovered_endpoints:
            if endpoint.path == path and endpoint.method == method:
                endpoint.is_alive = is_alive
                endpoint.status_code = status_code
                break
    
    def add_test_record(self, record: TestRecord):
        """添加测试记录"""
        self.context.test_history.append(record)
        
        if len(self.context.test_history) > 1000:
            self.context.test_history = self.context.test_history[-1000:]
    
    def set_phase(self, phase: TestPhase):
        """设置测试阶段"""
        old_phase = self.context.current_phase
        self.context.current_phase = phase
        
        self._emit_update('phase', old_phase, phase)
        self._record_change('phase_change', {'from': old_phase.value, 'to': phase.value})
    
    def set_user_preference(self, key: str, value: Any):
        """设置用户偏好"""
        self.context.user_preferences[key] = value
    
    def get_user_preference(self, key: str, default: Any = None) -> Any:
        """获取用户偏好"""
        return self.context.user_preferences.get(key, default)
    
    def get_relevant_context(self, for_phase: Optional[TestPhase] = None) -> Dict:
        """获取相关上下文"""
        if for_phase is None:
            for_phase = self.context.current_phase
        
        context_subset = {
            'target_url': self.context.target_url,
            'current_phase': for_phase.value,
        }
        
        if for_phase in [TestPhase.RECON, TestPhase.DISCOVERY]:
            context_subset['tech_stack'] = self.context.tech_stack.to_dict()
            context_subset['content'] = self.context.content.to_dict()
        
        elif for_phase in [TestPhase.TESTING, TestPhase.FUZZING]:
            context_subset['network'] = self.context.network.to_dict()
            context_subset['security'] = self.context.security.to_dict()
            context_subset['discovered_endpoints'] = [e.to_dict() for e in self.context.discovered_endpoints]
        
        elif for_phase == TestPhase.REPORT:
            context_subset['full_context'] = self.context.to_dict()
        
        return context_subset
    
    def get_high_value_endpoints(self) -> List[Endpoint]:
        """获取高价值端点"""
        return [e for e in self.context.discovered_endpoints if e.is_high_value]
    
    def get_alive_endpoints(self) -> List[Endpoint]:
        """获取存活端点"""
        return [e for e in self.context.discovered_endpoints if e.is_alive]
    
    def get_internal_addresses(self) -> Set[str]:
        """获取内网地址"""
        return self.context.content.internal_ips.copy()
    
    def needs_proxy(self) -> bool:
        """是否需要代理"""
        return bool(self.context.content.internal_ips) or self.context.network.requires_proxy
    
    def is_rate_limited(self) -> bool:
        """是否被限速"""
        return self.context.network.rate_limit_status in [
            RateLimitStatus.RATE_LIMITED,
            RateLimitStatus.BLOCKED
        ]
    
    def get_current_rate_limit(self) -> int:
        """获取当前速率限制"""
        status = self.context.network.rate_limit_status
        
        if status == RateLimitStatus.BLOCKED:
            return 0
        elif status == RateLimitStatus.RATE_LIMITED:
            return 1
        elif status == RateLimitStatus.WARNING:
            return 5
        else:
            return 10
    
    def export_context(self) -> Dict:
        """导出完整上下文"""
        return self.context.to_dict()
    
    def export_json(self) -> str:
        """导出 JSON 格式"""
        return json.dumps(self.export_context(), indent=2, default=str)
    
    def save_to_file(self, filepath: str):
        """保存上下文到文件"""
        with open(filepath, 'w') as f:
            json.dump(self.export_context(), f, indent=2, default=str)
    
    @classmethod
    def load_from_dict(cls, data: Dict) -> 'ContextManager':
        """从字典加载"""
        manager = cls(data['target_url'])
        
        if 'tech_stack' in data:
            ts = data['tech_stack']
            manager.context.tech_stack = TechStackContext(
                frontend=set(ts.get('frontend', [])),
                backend=set(ts.get('backend', [])),
                database=set(ts.get('database', [])),
                api_type=set(ts.get('api_type', [])),
                waf=ts.get('waf'),
                cdn=ts.get('cdn')
            )
        
        if 'network' in data:
            nw = data['network']
            manager.context.network = NetworkContext(
                is_reachable=nw.get('is_reachable', True),
                requires_proxy=nw.get('requires_proxy', False)
            )
        
        return manager
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'ContextManager':
        """从文件加载"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.load_from_dict(data)
    
    def _record_change(self, change_type: str, data: Any):
        """记录变更"""
        self._history.append({
            'timestamp': datetime.now().isoformat(),
            'type': change_type,
            'data': data
        })
    
    def get_history(self) -> List[Dict]:
        """获取变更历史"""
        return self._history.copy()
    
    def get_summary(self) -> Dict:
        """获取上下文摘要"""
        return {
            'target_url': self.context.target_url,
            'phase': self.context.current_phase.value,
            'tech_stack': {
                'frontend': list(self.context.tech_stack.frontend),
                'backend': list(self.context.tech_stack.backend),
                'waf': self.context.tech_stack.waf
            },
            'network': {
                'reachable': self.context.network.is_reachable,
                'rate_limit_status': self.context.network.rate_limit_status.value
            },
            'endpoints': {
                'total': len(self.context.discovered_endpoints),
                'alive': len(self.get_alive_endpoints()),
                'high_value': len(self.get_high_value_endpoints())
            },
            'content': {
                'is_spa': self.context.content.is_spa,
                'has_api_docs': self.context.content.has_api_docs,
                'internal_ips': list(self.context.content.internal_ips)
            }
        }


def create_context_manager(target_url: str) -> ContextManager:
    """创建上下文管理器工厂函数"""
    return ContextManager(target_url)


if __name__ == "__main__":
    cm = create_context_manager("http://example.com")
    
    cm.update_tech_stack({'frontend': {'vue', 'webpack'}, 'backend': {'spring'}})
    cm.set_waf("aliyun")
    cm.set_spa_mode(True, fallback_size=678)
    cm.add_swagger_url("http://example.com/api-docs")
    cm.mark_internal_address("10.0.0.1")
    cm.add_discovered_endpoint(Endpoint(path="/api/users", method="GET", score=8, is_high_value=True))
    cm.set_phase(TestPhase.DISCOVERY)
    
    print("Context Summary:")
    print(json.dumps(cm.get_summary(), indent=2))
    
    print("\nFull Context (JSON):")
    print(cm.export_json())
    
    print("\nHistory:")
    for h in cm.get_history():
        print(f"  {h['type']}: {h['data']}")
