#!/usr/bin/env python3
"""
Agentic Reasoning Engine - 智能推理引擎

多层级推理流程:
Surface → Context → Causal → Strategic

核心功能:
- 从表面现象到深层因果理解
- 规则引擎驱动的推理机制
- 置信度评估
- 洞察生成
"""

import re
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any, Callable, Type
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class UnderstandingLevel(Enum):
    """理解层级"""
    SURFACE = "surface"      # 表面现象
    CONTEXT = "context"      # 上下文理解
    CAUSAL = "causal"       # 因果推理
    STRATEGIC = "strategic" # 战略调整


class InsightType(Enum):
    """洞察类型"""
    OBSERVATION = "observation"      # 观察到的事实
    PATTERN = "pattern"              # 发现的模式
    INFERENCE = "inference"          # 推断
    BLOCKER = "blocker"              # 阻碍因素
    OPPORTUNITY = "opportunity"      # 机会
    STRATEGY_CHANGE = "strategy"    # 策略调整
    WARNING = "warning"              # 警告
    VALIDATION = "validation"        # 验证结果


@dataclass
class Finding:
    """推理发现"""
    what: str              # 观察到什么
    so_what: str           # 这意味着什么（核心）
    why: str               # 为什么（原因分析）
    implication: str       # 对测试的影响
    strategy: str          # 调整后的策略
    confidence: float      # 置信度 0-1
    level: UnderstandingLevel
    evidence: List[str] = field(default_factory=list)


@dataclass
class Insight:
    """洞察"""
    id: str
    type: InsightType
    content: str
    
    findings: List[Finding] = field(default_factory=list)
    
    source: str = ""                        # 哪个模块生成
    confidence: float = 1.0
    
    action_required: Optional[str] = None
    affected_strategies: List[str] = field(default_factory=list)
    
    generated_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None
    is_active: bool = True
    
    observations: List[str] = field(default_factory=list)  # 基于哪些观察
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.type.value,
            'content': self.content,
            'confidence': self.confidence,
            'findings': [{
                'what': f.what,
                'so_what': f.so_what,
                'why': f.why,
                'implication': f.implication,
                'strategy': f.strategy,
                'confidence': f.confidence,
                'level': f.level.value
            } for f in self.findings],
            'source': self.source,
            'action_required': self.action_required,
            'generated_at': self.generated_at.isoformat(),
            'is_active': self.is_active
        }


@dataclass
class Observation:
    """观察"""
    id: str
    timestamp: datetime
    url: str
    method: str
    
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    content_hash: str = ""
    
    is_html: bool = False
    is_json: bool = False
    is_xml: bool = False
    is_plain_text: bool = False
    
    spa_indicators: List[str] = field(default_factory=list)
    api_indicators: List[str] = field(default_factory=list)
    security_indicators: List[str] = field(default_factory=list)
    tech_fingerprints: Dict[str, Set[str]] = field(default_factory=dict)
    
    source: str = ""  # 'js', 'html', 'api', 'browser', 'fuzz'
    parent_url: Optional[str] = None
    parameters: Dict[str, str] = field(default_factory=dict)
    
    response_time: float = 0.0
    is_first_request: bool = False
    consecutive_failures: int = 0
    
    raw_content: str = ""  # 原始内容片段用于特征提取
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'url': self.url,
            'method': self.method,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'content_length': self.content_length,
            'is_html': self.is_html,
            'is_json': self.is_json,
            'spa_indicators': self.spa_indicators,
            'api_indicators': self.api_indicators,
            'tech_fingerprints': {k: list(v) for k, v in self.tech_fingerprints.items()}
        }


@dataclass
class ReasoningRule:
    """推理规则"""
    name: str
    description: str
    
    level: UnderstandingLevel
    
    condition: Callable[['Observation', List['Observation']], bool]
    
    findings_builder: Callable[['Observation', List['Observation']], Finding]
    
    priority: int = 0
    
    enabled: bool = True
    
    @dataclass
    class Result:
        rule_name: str
        triggered: bool
        finding: Optional[Finding] = None
        confidence: float = 0.0


class InsightStore:
    """洞察存储"""
    
    def __init__(self):
        self.insights: List[Insight] = []
        self.insights_by_type: Dict[InsightType, List[Insight]] = defaultdict(list)
        self.insights_by_source: Dict[str, List[Insight]] = defaultdict(list)
        
        self.learning_history: List[Dict] = []
    
    def add(self, insight: Insight):
        """添加洞察"""
        self.insights.append(insight)
        self.insights_by_type[insight.type].append(insight)
        self.insights_by_source[insight.source].append(insight)
    
    def get_active(self) -> List[Insight]:
        """获取活跃洞察"""
        now = datetime.now()
        return [i for i in self.insights if i.is_active and 
                (i.valid_until is None or i.valid_until > now)]
    
    def get_by_type(self, insight_type: InsightType) -> List[Insight]:
        """按类型获取洞察"""
        return self.insights_by_type.get(insight_type, [])
    
    def get_by_source(self, source: str) -> List[Insight]:
        """按来源获取洞察"""
        return self.insights_by_source.get(source, [])
    
    def deactivate(self, insight_id: str):
        """停用洞察"""
        for insight in self.insights:
            if insight.id == insight_id:
                insight.is_active = False
    
    def record_learning(self, pattern: str, outcome: str, effectiveness: float):
        """记录学习结果"""
        self.learning_history.append({
            'pattern': pattern,
            'outcome': outcome,
            'effectiveness': effectiveness,
            'timestamp': datetime.now()
        })
    
    def get_summary(self) -> Dict:
        """获取洞察摘要"""
        active = self.get_active()
        return {
            'total_insights': len(self.insights),
            'active_insights': len(active),
            'by_type': {t.value: len(self.insights_by_type[t]) for t in InsightType},
            'learning_history_size': len(self.learning_history)
        }


class Reasoner:
    """
    推理引擎
    
    执行多层级推理:
    1. Surface Level: 识别响应类型和基本特征
    2. Context Level: 理解上下文关联
    3. Causal Level: 推断因果关系
    4. Strategic Level: 制定调整策略
    """
    
    def __init__(self):
        self.rules: List[ReasoningRule] = []
        self.observation_history: List[Observation] = []
        self.insight_store = InsightStore()
        
        self._register_default_rules()
    
    def _register_default_rules(self):
        """注册默认推理规则"""
        self.register_rule(self._create_spa_fallback_rule())
        self.register_rule(self._create_json_request_html_response_rule())
        self.register_rule(self._create_internal_ip_rule())
        self.register_rule(self._create_waf_detection_rule())
        self.register_rule(self._create_tech_fingerprint_rule())
        self.register_rule(self._create_error_leak_rule())
        self.register_rule(self._create_auth_detection_rule())
        self.register_rule(self._create_swagger_discovery_rule())
    
    def register_rule(self, rule: ReasoningRule):
        """注册推理规则"""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        logger.debug(f"Registered reasoning rule: {rule.name}")
    
    def observe_and_reason(self, response_data: Dict, session: Any = None) -> List[Insight]:
        """
        观察并推理
        
        Args:
            response_data: 响应数据字典
            session: 可选的 session 用于关联分析
        
        Returns:
            生成的洞察列表
        """
        observation = self._create_observation(response_data)
        self.observation_history.append(observation)
        
        return self.reason(observation)
    
    def reason(self, observation: Observation) -> List[Insight]:
        """
        执行多层级推理
        
        Args:
            observation: 当前观察
        
        Returns:
            生成的洞察列表
        """
        insights = []
        
        recent_obs = self.observation_history[-20:]
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            try:
                triggered = rule.condition(observation, recent_obs)
                
                if triggered:
                    finding = rule.findings_builder(observation, recent_obs)
                    
                    if finding:
                        insight = Insight(
                            id=self._generate_insight_id(),
                            type=self._rule_to_insight_type(rule),
                            content=finding.so_what,
                            findings=[finding],
                            source=f"reasoner:{rule.name}",
                            confidence=finding.confidence,
                            action_required=finding.strategy if finding.confidence < 0.9 else None,
                            observations=[observation.id]
                        )
                        
                        insights.append(insight)
                        self.insight_store.add(insight)
                        
                        logger.info(f"Rule triggered: {rule.name} → {insight.content}")
            
            except Exception as e:
                logger.warning(f"Rule evaluation error ({rule.name}): {e}")
        
        if len(recent_obs) >= 3:
            pattern_insights = self._detect_patterns(recent_obs)
            insights.extend(pattern_insights)
        
        return insights
    
    def _detect_patterns(self, observations: List[Observation]) -> List[Insight]:
        """检测观察模式"""
        insights = []
        
        html_obs = [o for o in observations if o.is_html]
        if len(html_obs) >= 3:
            lengths = [o.content_length for o in html_obs]
            if len(set(lengths)) == 1:
                length = lengths[0]
                
                finding = Finding(
                    what=f"所有 {len(html_obs)} 个不同路径返回完全相同大小的 HTML ({length} 字节)",
                    so_what="这是典型的 SPA (Vue.js/React) fallback 行为",
                    why="前端服务器配置了 catch-all 路由，将所有请求都路由到 index.html",
                    implication="后端 API 不在当前服务器，可能在内网或使用不同的地址",
                    strategy="1. 从 JS 中提取后端 API 地址 2. 尝试不同端口/路径探测 3. 如内网地址需要代理访问",
                    confidence=0.95,
                    level=UnderstandingLevel.CAUSAL,
                    evidence=[f"{o.url} ({o.content_length} bytes)" for o in html_obs[:5]]
                )
                
                insight = Insight(
                    id=self._generate_insight_id(),
                    type=InsightType.PATTERN,
                    content=finding.so_what,
                    findings=[finding],
                    source="reasoner:spa_fallback_pattern",
                    confidence=0.95,
                    action_required=finding.strategy
                )
                insights.append(insight)
                self.insight_store.add(insight)
        
        return insights
    
    def reason_from_pattern(self, observations: List[Observation]) -> Optional[Insight]:
        """从观察模式中推理"""
        if len(observations) < 2:
            return None
        
        first = observations[0]
        last = observations[-1]
        
        if first.content_hash == last.content_hash and first.url != last.url:
            return Insight(
                id=self._generate_insight_id(),
                type=InsightType.PATTERN,
                content="不同 URL 返回完全相同内容",
                source="reasoner:content_similarity",
                confidence=0.7
            )
        
        return None
    
    def estimate_confidence(self, evidence: List[Any], historical_accuracy: float = 0.8) -> float:
        """
        评估置信度
        
        基于:
        - 证据数量
        - 一致性
        - 历史准确率
        """
        if not evidence:
            return 0.3
        
        evidence_factor = min(len(evidence) / 5.0, 1.0) * 0.3
        
        consistency_factor = 0.4
        
        historical_factor = historical_accuracy * 0.3
        
        confidence = evidence_factor + consistency_factor + historical_factor
        
        return min(max(confidence, 0.0), 1.0)
    
    def _create_observation(self, response_data: Dict) -> Observation:
        """从响应数据创建观察"""
        content = response_data.get('content', '')
        content_hash = hashlib.md5(content[:1000].encode()).hexdigest() if content else ""
        
        obs = Observation(
            id=self._generate_observation_id(),
            timestamp=datetime.now(),
            url=response_data.get('url', ''),
            method=response_data.get('method', 'GET'),
            status_code=response_data.get('status_code', 0),
            content_type=response_data.get('content_type', ''),
            content_length=len(content),
            content_hash=content_hash,
            is_html=self._check_html(content),
            is_json=self._check_json(content),
            is_xml=self._check_xml(content),
            source=response_data.get('source', 'unknown'),
            response_time=response_data.get('response_time', 0.0),
            raw_content=content[:500] if content else ""
        )
        
        obs.spa_indicators = self._detect_spa_indicators(content)
        obs.api_indicators = self._detect_api_indicators(content)
        obs.security_indicators = self._detect_security_indicators(content)
        obs.tech_fingerprints = self._detect_tech_fingerprints(response_data, content)
        
        return obs
    
    def _check_html(self, content: str) -> bool:
        if not content:
            return False
        content_lower = content.lower()
        return '<!doctype' in content_lower or '<html' in content_lower or '<!doctype html>' in content_lower
    
    def _check_json(self, content: str) -> bool:
        if not content:
            return False
        try:
            import json
            json.loads(content)
            return True
        except:
            return False
    
    def _check_xml(self, content: str) -> bool:
        if not content:
            return False
        return '<?xml' in content or '<root' in content
    
    def _detect_spa_indicators(self, content: str) -> List[str]:
        indicators = []
        if not content:
            return indicators
        content_lower = content.lower()
        
        spa_patterns = {
            'webpack_chunk_vendors': r'chunk-vendors',
            'div_id_app': r'<div[^>]+id=["\']app["\']',
            'div_id_root': r'<div[^>]+id=["\']root["\']',
            'vue_keyword': r'vue',
            'react_keyword': r'react',
            'angular_keyword': r'angular',
            'ng_app': r'ng-app',
            'next_js': r'__NEXT_DATA__',
            'nuxt_js': r'__nuxt',
        }
        
        for name, pattern in spa_patterns.items():
            if re.search(pattern, content_lower):
                indicators.append(name)
        
        return indicators
    
    def _detect_api_indicators(self, content: str) -> List[str]:
        indicators = []
        if not content:
            return indicators
        content_lower = content.lower()
        
        api_patterns = {
            'swagger': r'swagger',
            'openapi': r'openapi',
            'api_paths': r'/api/',
            'graphql': r'__schema',
            'rest_paths': r'/v\d+/',
        }
        
        for name, pattern in api_patterns.items():
            if re.search(pattern, content_lower):
                indicators.append(name)
        
        return indicators
    
    def _detect_security_indicators(self, content: str) -> List[str]:
        indicators = []
        if not content:
            return indicators
        content_lower = content.lower()
        
        security_patterns = {
            'sql_error': r'sql.*(error|syntax|warning)',
            'mysql_error': r'mysql',
            'postgresql_error': r'postgresql|psql',
            'oracle_error': r'oracle',
            'xss_reflect': r'<script|javascript:',
            'auth_required': r'(unauthorized|401|login|auth)',
            'forbidden': r'(forbidden|403|access denied)',
            'error_disclosure': r'(exception|stack trace|at .+\.java)',
        }
        
        for name, pattern in security_patterns.items():
            if re.search(pattern, content_lower):
                indicators.append(name)
        
        return indicators
    
    def _detect_tech_fingerprints(self, response_data: Dict, content: str) -> Dict[str, Set[str]]:
        fingerprints: Dict[str, Set[str]] = defaultdict(set)
        
        headers = response_data.get('headers', {})
        
        header_fingerprints = {
            'server': {
                'nginx': r'nginx',
                'apache': r'apache',
                'iis': r'microsoft-iis',
                'express': r'express',
                'kestrel': r'kestrel',
            },
            'x_powered_by': {
                'php': r'php',
                'asp.net': r'asp\.net',
                'express': r'express',
                'spring': r'spring',
                'django': r'django',
                'flask': r'flask',
            }
        }
        
        for header, patterns in header_fingerprints.items():
            header_value = headers.get(header, '')
            if header_value:
                for tech, pattern in patterns.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        fingerprints[header].add(tech)
        
        content_lower = content.lower() if content else ''
        
        content_fingerprints = {
            'frontend': {
                'vue': r'vue(\.runtime)?\.js',
                'react': r'react\.js|react-dom',
                'angular': r'@angular|angular\.js',
                'jquery': r'jquery',
                'bootstrap': r'bootstrap(\.min)?\.js',
                'tailwind': r'tailwindcss',
            },
            'backend': {
                'spring': r'spring|org\.springframework',
                'django': r'django',
                'flask': r'flask',
                'express': r'express',
                'laravel': r'laravel',
                'rails': r'ruby-on-rails',
            }
        }
        
        for category, patterns in content_fingerprints.items():
            for tech, pattern in patterns.items():
                if re.search(pattern, content_lower):
                    fingerprints[category].add(tech)
        
        return fingerprints
    
    def _create_spa_fallback_rule(self) -> ReasoningRule:
        """SPA Fallback 检测规则"""
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            if not obs.is_html:
                return False
            
            html_obs = [o for o in history if o.is_html]
            if len(html_obs) < 3:
                return False
            
            lengths = [o.content_length for o in html_obs]
            return len(set(lengths)) == 1
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            length = obs.content_length
            count = len([o for o in history if o.is_html])
            
            return Finding(
                what=f"所有 {count} 个不同路径返回完全相同大小的 HTML ({length} 字节)",
                so_what="这是典型的 SPA (Vue.js/React) fallback 行为",
                why="前端服务器(Nginx)配置了 catch-all 路由，将所有请求都路由到 index.html",
                implication="后端 API 不在当前服务器，可能在内网或使用不同的地址",
                strategy="1. 从 JS 中提取后端 API 地址 2. 尝试不同端口/路径探测 3. 如内网地址需要代理访问",
                confidence=0.95,
                level=UnderstandingLevel.CAUSAL,
                evidence=[f"{o.url}" for o in history[-5:] if o.is_html]
            )
        
        return ReasoningRule(
            name="spa_fallback_detection",
            description="检测 SPA fallback 行为",
            level=UnderstandingLevel.CAUSAL,
            condition=condition,
            findings_builder=findings_builder,
            priority=100
        )
    
    def _create_json_request_html_response_rule(self) -> ReasoningRule:
        """JSON 请求返回 HTML 的矛盾检测"""
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            url_lower = obs.url.lower()
            is_json_request = any(ext in url_lower for ext in ['.json', 'swagger', 'api-docs', 'openapi'])
            
            return is_json_request and obs.is_html
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            return Finding(
                what=f"请求 JSON 相关路径 ({obs.url}) 但返回 HTML",
                so_what="该路径在服务端不存在，是前端在模拟",
                why="后端 API 服务器与前端分离，SPA fallback 导致请求被发到前端",
                implication="无法通过前端服务器访问真正的 API 文档",
                strategy="1. 从 JS 或网络请求中识别后端真实地址 2. 直接测试后端地址",
                confidence=0.9,
                level=UnderstandingLevel.CAUSAL,
                evidence=[obs.url]
            )
        
        return ReasoningRule(
            name="json_request_html_response",
            description="检测 JSON 请求返回 HTML 的矛盾",
            level=UnderstandingLevel.CAUSAL,
            condition=condition,
            findings_builder=findings_builder,
            priority=90
        )
    
    def _create_internal_ip_rule(self) -> ReasoningRule:
        """内网地址发现规则"""
        
        INTERNAL_IP_PATTERNS = [
            r'10\.\d+\.\d+\.\d+',
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'127\.\d+\.\d+\.\d+',
            r'localhost',
        ]
        
        INTERNAL_HOST_PATTERNS = [
            r'\.internal\.',
            r'\.local$',
            r'\.corp\.',
            r'\.internal\.',
        ]
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            content = obs.raw_content
            if not content:
                return False
            
            for pattern in INTERNAL_IP_PATTERNS + INTERNAL_HOST_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            ips = []
            hosts = []
            content = obs.raw_content
            
            for pattern in INTERNAL_IP_PATTERNS:
                ips.extend(re.findall(pattern, content))
            
            for pattern in INTERNAL_HOST_PATTERNS:
                hosts.extend(re.findall(pattern, content, re.IGNORECASE))
            
            all_addresses = ips + hosts
            
            return Finding(
                what=f"从响应中发现内网地址: {all_addresses[:3]}",
                so_what="后端 API 在内网环境，前端无法直接访问",
                why="系统采用前后端分离架构，后端部署在内网",
                implication="无法从外部直接测试后端 API",
                strategy="1. 标记内网地址 2. 建议通过代理工具访问 3. 寻找外网暴露的测试环境",
                confidence=0.95,
                level=UnderstandingLevel.STRATEGIC,
                evidence=all_addresses[:5]
            )
        
        return ReasoningRule(
            name="internal_ip_discovery",
            description="发现内网地址",
            level=UnderstandingLevel.STRATEGIC,
            condition=condition,
            findings_builder=findings_builder,
            priority=110
        )
    
    def _create_waf_detection_rule(self) -> ReasoningRule:
        """WAF 检测规则"""
        
        WAF_SIGNATURES = {
            '360': [r'360waf', r'360safe'],
            'aliyun': [r'aliyuncs\.com', r' Alibaba Cloud'],
            'tencent': [r'tencent-cloud\.net', r'WAF', r'Tencent Cloud'],
            'aws': [r'aws-waf', r'AWSWAF'],
            'cloudflare': [r'cloudflare', r'__cfduid'],
            'imperva': [r'imperva', r'incapsula'],
            'fortinet': [r'fortigate', r'fortiweb'],
            'akamai': [r'akamai', r'akamaigas'],
        }
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            content = obs.raw_content.lower()
            headers_str = str(obs.status_code)
            
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if re.search(sig, content, re.IGNORECASE) or re.search(sig, headers_str, re.IGNORECASE):
                        return True
            
            if obs.status_code == 403:
                return True
            
            return False
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            detected_waf = "未知 WAF"
            
            content = obs.raw_content.lower()
            
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    if re.search(sig, content, re.IGNORECASE):
                        detected_waf = waf
                        break
            
            return Finding(
                what=f"检测到 WAF 特征: {detected_waf}",
                so_what="目标受 WAF 保护，需要使用绕过技术",
                why="WAF 会拦截明显的攻击尝试",
                implication="标准 payload 可能被拦截",
                strategy="1. 激活 WAF 绕过策略 2. 使用编码和混淆 3. 尝试绕过 WAF 的已知弱点",
                confidence=0.85,
                level=UnderstandingLevel.STRATEGIC,
                evidence=[f"Status: {obs.status_code}"]
            )
        
        return ReasoningRule(
            name="waf_detection",
            description="检测 WAF 防护",
            level=UnderstandingLevel.STRATEGIC,
            condition=condition,
            findings_builder=findings_builder,
            priority=105
        )
    
    def _create_tech_fingerprint_rule(self) -> ReasoningRule:
        """技术栈指纹识别规则"""
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            return bool(obs.tech_fingerprints)
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            techs = []
            
            for category, fingerprints in obs.tech_fingerprints.items():
                for fp in fingerprints:
                    techs.append(f"{category}:{fp}")
            
            return Finding(
                what=f"识别到技术栈: {', '.join(techs[:5])}",
                so_what="目标使用特定技术栈，可以针对性地测试",
                why="通过响应头和内容特征识别",
                implication="可以使用针对该技术栈的专项测试",
                strategy=f"1. 启用 {techs[0] if techs else '通用'} 专项测试 2. 调整 payload 适配技术栈",
                confidence=0.8,
                level=UnderstandingLevel.CONTEXT,
                evidence=techs
            )
        
        return ReasoningRule(
            name="tech_fingerprint",
            description="识别技术栈指纹",
            level=UnderstandingLevel.CONTEXT,
            condition=condition,
            findings_builder=findings_builder,
            priority=50
        )
    
    def _create_error_leak_rule(self) -> ReasoningRule:
        """错误信息泄露检测"""
        
        ERROR_PATTERNS = [
            (r'SQL syntax|MySQL', 'MySQL SQL 错误'),
            (r'PostgreSQL.*ERROR|PSQL', 'PostgreSQL 错误'),
            (r'Oracle.*Exception|java\.sql', 'Java SQL 错误'),
            (r'Syntax error.*Python|Traceback.*Python', 'Python 错误'),
            (r'Syntax error.*PHP|php error', 'PHP 错误'),
            (r'Stack trace|at\s+\w+\.\w+\(', '堆栈跟踪泄露'),
            (r'file_get_contents|fopen.*failed', '文件操作错误'),
            (r'Connection.*refused|Connection.*timeout', '连接错误'),
        ]
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            content = obs.raw_content.lower()
            
            for pattern, _ in ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            detected_errors = []
            
            content = obs.raw_content
            
            for pattern, name in ERROR_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_errors.append(name)
            
            return Finding(
                what=f"发现错误信息泄露: {', '.join(detected_errors[:3])}",
                so_what="应用泄露了技术栈和错误细节",
                why="错误处理不当导致敏感信息输出",
                implication="可用于指纹识别和针对性攻击",
                strategy="1. 收集所有错误信息 2. 用于指纹识别 3. 利用错误信息辅助 SQL 注入",
                confidence=0.85,
                level=UnderstandingLevel.CONTEXT,
                evidence=detected_errors
            )
        
        return ReasoningRule(
            name="error_leak_detection",
            description="检测错误信息泄露",
            level=UnderstandingLevel.CONTEXT,
            condition=condition,
            findings_builder=findings_builder,
            priority=70
        )
    
    def _create_auth_detection_rule(self) -> ReasoningRule:
        """认证机制检测"""
        
        AUTH_PATTERNS = {
            'jwt': [r'eyJ[a-zA-Z0-9_-]*\.eyJ', r'jwt-token', r'Bearer\s+\w+'],
            'session': [r'sessionid', r'session_id', r'SESSIONID', r'PHPSESSID', r'JSESSIONID'],
            'basic': [r'Authorization:\s*Basic', r'auth_basic'],
            'oauth': [r'oauth', r'OAuth', r'access_token', r'refresh_token'],
        }
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            url_lower = obs.url.lower()
            content_lower = obs.raw_content.lower()
            headers = str(obs.status_code)
            
            auth_keywords = ['login', 'signin', 'auth', 'token', 'password', 'credential']
            
            for keyword in auth_keywords:
                if keyword in url_lower:
                    return True
            
            for auth_type, patterns in AUTH_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower, re.IGNORECASE):
                        return True
            
            if obs.status_code in [401, 403]:
                return True
            
            return False
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            auth_types = []
            content_lower = obs.raw_content
            
            for auth_type, patterns in AUTH_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower, re.IGNORECASE):
                        auth_types.append(auth_type)
                        break
            
            return Finding(
                what=f"检测到认证机制: {', '.join(auth_types) if auth_types else '需要认证'}",
                so_what="接口需要认证或使用了特定认证方式",
                why="响应头或内容中包含认证相关信息",
                implication="测试时需要考虑认证绕过",
                strategy="1. 收集认证相关信息 2. 测试 JWT/Token 安全 3. 检查认证绕过漏洞",
                confidence=0.75,
                level=UnderstandingLevel.CONTEXT,
                evidence=auth_types
            )
        
        return ReasoningRule(
            name="auth_detection",
            description="检测认证机制",
            level=UnderstandingLevel.CONTEXT,
            condition=condition,
            findings_builder=findings_builder,
            priority=60
        )
    
    def _create_swagger_discovery_rule(self) -> ReasoningRule:
        """Swagger/API 文档发现"""
        
        SWAGGER_PATTERNS = [
            r'swagger-ui', r'swagger-ui\.html',
            r'api-docs', r'/swagger/',
            r'openapi', r'/v\d+/api-docs',
        ]
        
        def condition(obs: Observation, history: List[Observation]) -> bool:
            url_lower = obs.url.lower()
            
            for pattern in SWAGGER_PATTERNS:
                if re.search(pattern, url_lower):
                    return True
            
            content_lower = obs.raw_content.lower()
            if 'swagger' in content_lower or 'openapi' in content_lower:
                return True
            
            return False
        
        def findings_builder(obs: Observation, history: List[Observation]) -> Finding:
            return Finding(
                what=f"发现 API 文档路径: {obs.url}",
                so_what="存在可访问的 API 文档，可能泄露敏感信息",
                why="服务器配置允许访问 API 文档",
                implication="可以直接从文档获取 API 结构",
                strategy="1. 访问 API 文档获取完整端点列表 2. 分析文档中的敏感接口 3. 尝试未文档化的端点",
                confidence=0.9,
                level=UnderstandingLevel.STRATEGIC,
                evidence=[obs.url]
            )
        
        return ReasoningRule(
            name="swagger_discovery",
            description="发现 Swagger/API 文档",
            level=UnderstandingLevel.STRATEGIC,
            condition=condition,
            findings_builder=findings_builder,
            priority=80
        )
    
    def _rule_to_insight_type(self, rule: ReasoningRule) -> InsightType:
        """根据规则层级映射到洞察类型"""
        mapping = {
            UnderstandingLevel.SURFACE: InsightType.OBSERVATION,
            UnderstandingLevel.CONTEXT: InsightType.INFERENCE,
            UnderstandingLevel.CAUSAL: InsightType.PATTERN,
            UnderstandingLevel.STRATEGIC: InsightType.STRATEGY_CHANGE,
        }
        return mapping.get(rule.level, InsightType.INFERENCE)
    
    def _generate_observation_id(self) -> str:
        return f"obs_{int(time.time() * 1000)}"
    
    def _generate_insight_id(self) -> str:
        return f"ins_{int(time.time() * 1000)}"
    
    def get_insight_store(self) -> InsightStore:
        """获取洞察存储"""
        return self.insight_store
    
    def get_observations(self) -> List[Observation]:
        """获取观察历史"""
        return self.observation_history


def create_reasoner() -> Reasoner:
    """创建推理引擎的工厂函数"""
    return Reasoner()


if __name__ == "__main__":
    import json
    
    reasoner = create_reasoner()
    
    test_responses = [
        {
            'url': 'http://example.com/login',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': '<!DOCTYPE html><html><div id="app"></div><script src="/static/js/chunk-vendors.js"></script></html>' * 10,
            'source': 'html',
            'response_time': 0.5
        },
        {
            'url': 'http://example.com/admin',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': '<!DOCTYPE html><html><div id="app"></div><script src="/static/js/chunk-vendors.js"></script></html>' * 10,
            'source': 'html',
            'response_time': 0.5
        },
        {
            'url': 'http://example.com/api/swagger.json',
            'method': 'GET',
            'status_code': 200,
            'content_type': 'text/html',
            'content': '<!DOCTYPE html><html><div id="app"></div></html>' * 10,
            'source': 'api',
            'response_time': 0.3
        }
    ]
    
    for resp in test_responses:
        insights = reasoner.observe_and_reason(resp)
        
        print(f"\n[*] URL: {resp['url']}")
        for insight in insights:
            print(f"    Insight: {insight.content}")
            if insight.findings:
                f = insight.findings[0]
                print(f"    → What: {f.what}")
                print(f"    → So What: {f.so_what}")
                print(f"    → Confidence: {f.confidence}")
    
    print("\n[*] Insight Store Summary:")
    summary = reasoner.insight_store.get_summary()
    print(json.dumps(summary, indent=2))
