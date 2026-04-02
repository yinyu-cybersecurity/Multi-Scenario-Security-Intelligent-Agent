#!/usr/bin/env python3
"""
Strategy Pool - 策略池系统

动态策略管理：
- 预定义策略库（8种策略）
- 策略选择算法
- 策略适应性调整
- 策略有效性评估
"""

import time
import json
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class StrategyState(Enum):
    """策略状态"""
    IDLE = "idle"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Condition:
    """策略激活条件"""
    type: str           # 'insight_type', 'tech_stack', 'network_status', 'endpoint_score'
    operator: str       # 'equals', 'contains', 'greater_than', 'less_than', 'in'
    value: Any
    
    def evaluate(self, context: 'StrategyContext') -> bool:
        """评估条件是否满足"""
        if self.type == 'insight_type':
            insight_types = context.get('insight_types', [])
            if self.operator == 'contains':
                return self.value in insight_types
            elif self.operator == 'in':
                return self.value in insight_types
        
        elif self.type == 'tech_stack':
            tech_stack = context.get('tech_stack', {})
            if self.operator == 'contains':
                return self.value in tech_stack
        
        elif self.type == 'network_status':
            status = context.get('network_status', 'normal')
            if self.operator == 'equals':
                return status == self.value
            elif self.operator == 'in':
                return status in self.value
        
        elif self.type == 'endpoint_score':
            score = context.get('endpoint_score', 0)
            if self.operator == 'greater_than':
                return score > self.value
            elif self.operator == 'greater_equal':
                return score >= self.value
            elif self.operator == 'equals':
                return score == self.value
        
        elif self.type == 'endpoint_type':
            endpoint_path = context.get('endpoint_path', '').lower()
            if self.operator == 'contains':
                return self.value in endpoint_path
        
        elif self.type == 'waf_detected':
            waf = context.get('waf_detected')
            if self.operator == 'equals':
                return waf == self.value
            elif self.operator == 'is_not_none':
                return waf is not None
        
        elif self.type == 'is_spa':
            is_spa = context.get('is_spa', False)
            return is_spa == self.value
        
        elif self.type == 'has_internal_ips':
            internal_ips = context.get('internal_ips', set())
            return len(internal_ips) > 0 if self.value else len(internal_ips) == 0
        
        return False


@dataclass
class Action:
    """策略动作"""
    type: str           # 'test_sqli', 'test_xss', 'fuzz_path', etc.
    params: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    timeout: float = 30.0
    retry_on_failure: int = 1
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'params': self.params,
            'priority': self.priority,
            'timeout': self.timeout,
            'retry_on_failure': self.retry_on_failure
        }


@dataclass
class StrategyMetrics:
    """策略指标"""
    success_count: int = 0
    failure_count: int = 0
    total_executions: int = 0
    avg_effectiveness: float = 0.0
    last_execution_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    
    def record_execution(self, success: bool, effectiveness: float = 0.0):
        """记录执行结果"""
        self.total_executions += 1
        if success:
            self.success_count += 1
            self.last_success_time = datetime.now()
        else:
            self.failure_count += 1
        
        if self.total_executions > 0:
            self.avg_effectiveness = (
                (self.avg_effectiveness * (self.total_executions - 1) + effectiveness) 
                / self.total_executions
            )
        
        self.last_execution_time = datetime.now()
    
    def to_dict(self) -> Dict:
        return {
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'total_executions': self.total_executions,
            'avg_effectiveness': self.avg_effectiveness,
            'last_execution_time': self.last_execution_time.isoformat() if self.last_execution_time else None,
            'success_rate': self.success_count / max(self.total_executions, 1)
        }


@dataclass
class Strategy:
    """策略"""
    id: str
    name: str
    description: str
    
    activation_conditions: List[Condition] = field(default_factory=list)
    priority: int = 0
    
    actions: List[Action] = field(default_factory=list)
    execution_order: str = "sequential"  # 'sequential', 'parallel', 'adaptive'
    
    exit_on: List[str] = field(default_factory=list)  # 'all_complete', 'vuln_found', 'blocked'
    max_duration: float = 300.0
    max_iterations: int = 100
    
    is_adaptive: bool = False
    adaptation_threshold: float = 0.3
    
    state: StrategyState = StrategyState.IDLE
    metrics: StrategyMetrics = field(default_factory=StrategyMetrics)
    
    config: Dict[str, Any] = field(default_factory=dict)
    
    def is_active(self) -> bool:
        return self.state == StrategyState.ACTIVE
    
    def can_activate(self, context: 'StrategyContext') -> bool:
        """检查是否可以激活"""
        if not self.activation_conditions:
            return True
        
        for cond in self.activation_conditions:
            if not cond.evaluate(context):
                return False
        
        return True
    
    def should_exit(self, exit_reason: str, vulns_found: int = 0) -> bool:
        """检查是否应该退出"""
        if exit_reason in self.exit_on:
            return True
        
        if 'vuln_found' in self.exit_on and vulns_found > 0:
            return True
        
        return False
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'priority': self.priority,
            'state': self.state.value,
            'metrics': self.metrics.to_dict(),
            'actions': [a.to_dict() for a in self.actions],
            'config': self.config
        }


class StrategyContext(Dict):
    """策略上下文（字典-like）"""
    
    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


@dataclass
class StrategyPlan:
    """策略计划"""
    primary_strategy: Strategy
    fallback_strategy: Optional[Strategy] = None
    
    execution_order: List[str] = field(default_factory=list)
    adaptations: Dict[str, Any] = field(default_factory=dict)
    
    estimated_duration: float = 0.0
    estimated_actions: int = 0


class StrategyPool:
    """
    策略池
    
    包含预定义策略库和策略选择逻辑
    """
    
    def __init__(self):
        self.strategies: Dict[str, Strategy] = {}
        self._register_default_strategies()
    
    def _register_default_strategies(self):
        """注册默认策略"""
        self.register_strategy(self._create_default_strategy())
        self.register_strategy(self._create_waf_bypass_strategy())
        self.register_strategy(self._create_spa_fallback_strategy())
        self.register_strategy(self._create_internal_address_strategy())
        self.register_strategy(self._create_high_value_endpoint_strategy())
        self.register_strategy(self._create_auth_testing_strategy())
        self.register_strategy(self._create_rate_limited_strategy())
        self.register_strategy(self._create_sensitive_operation_strategy())
    
    def register_strategy(self, strategy: Strategy):
        """注册策略"""
        self.strategies[strategy.id] = strategy
        logger.debug(f"Registered strategy: {strategy.id}")
    
    def get_strategy(self, strategy_id: str) -> Optional[Strategy]:
        """获取策略"""
        return self.strategies.get(strategy_id)
    
    def get_all_strategies(self) -> List[Strategy]:
        """获取所有策略"""
        return list(self.strategies.values())
    
    def select_strategy(self, context: StrategyContext, insights: List[Any] = None) -> Strategy:
        """
        根据上下文选择最佳策略
        
        选择逻辑：
        1. 检查所有可激活策略
        2. 按优先级排序
        3. 返回最高优先级策略
        """
        if insights is None:
            insights = []
        
        context['insight_types'] = [i.type for i in insights] if hasattr(insights, '__iter__') else []
        
        activatable = []
        for strategy in self.strategies.values():
            if strategy.can_activate(context):
                activatable.append((strategy.priority, strategy.id, strategy))
        
        if not activatable:
            return self.strategies['default']
        
        activatable.sort(key=lambda x: x[0], reverse=True)
        
        selected = activatable[0][2]
        selected.state = StrategyState.ACTIVE
        
        logger.info(f"Selected strategy: {selected.id} ({selected.name})")
        
        return selected
    
    def select_multiple(self, context: StrategyContext, max_strategies: int = 3) -> List[Strategy]:
        """选择多个策略"""
        activatable = []
        for strategy in self.strategies.values():
            if strategy.can_activate(context):
                activatable.append((strategy.priority, id(strategy), strategy))
        
        if not activatable:
            return [self.strategies['default']]
        
        activatable.sort(key=lambda x: x[0], reverse=True)
        
        return [s[2] for s in activatable[:max_strategies]]
    
    def create_plan(self, context: StrategyContext, insights: List[Any] = None) -> StrategyPlan:
        """创建策略计划"""
        primary = self.select_strategy(context, insights)
        
        estimated_actions = len(primary.actions)
        estimated_duration = sum(a.timeout for a in primary.actions)
        
        return StrategyPlan(
            primary_strategy=primary,
            fallback_strategy=self.strategies.get('default'),
            execution_order=[primary.id],
            estimated_duration=estimated_duration,
            estimated_actions=estimated_actions
        )
    
    def adapt_strategy(self, strategy: Strategy, feedback: Dict) -> Strategy:
        """根据反馈调整策略"""
        if not strategy.is_adaptive:
            return strategy
        
        effectiveness = feedback.get('effectiveness', 0.0)
        
        if effectiveness < strategy.adaptation_threshold:
            for action in strategy.actions:
                if action.type == 'test_sqli' or action.type == 'test_xss':
                    action.params['use_bypass'] = True
                    action.params['obfuscation_level'] = 'high'
        
        return strategy
    
    def record_outcome(self, strategy_id: str, success: bool, effectiveness: float = 0.0):
        """记录策略执行结果"""
        strategy = self.strategies.get(strategy_id)
        if strategy:
            strategy.metrics.record_execution(success, effectiveness)
            
            if success:
                logger.info(f"Strategy {strategy_id} succeeded (effectiveness: {effectiveness:.2f})")
            else:
                logger.warning(f"Strategy {strategy_id} failed")
    
    def _create_default_strategy(self) -> Strategy:
        """创建默认策略"""
        return Strategy(
            id='default',
            name='默认测试策略',
            description='适用于大多数目标的默认测试策略',
            priority=0,
            actions=[
                Action(type='discover_endpoints', priority=10),
                Action(type='test_sqli', priority=8),
                Action(type='test_xss', priority=8),
                Action(type='test_auth', priority=6),
            ],
            execution_order='sequential',
            exit_on=['all_complete', 'vuln_found', 'blocked'],
            config={
                'rate_limit': 10,
                'payload_set': 'standard',
                'depth': 'normal'
            }
        )
    
    def _create_waf_bypass_strategy(self) -> Strategy:
        """创建 WAF 绕过策略"""
        return Strategy(
            id='waf_detected',
            name='WAF 绕过策略',
            description='当检测到 WAF 时使用的绕过策略',
            priority=10,
            activation_conditions=[
                Condition(type='waf_detected', operator='is_not_none', value=None)
            ],
            actions=[
                Action(type='test_sqli_bypass', priority=10, params={'obfuscation_level': 'high'}),
                Action(type='test_xss_bypass', priority=10, params={'obfuscation_level': 'high'}),
                Action(type='test_obfuscated', priority=8),
            ],
            execution_order='sequential',
            exit_on=['all_complete', 'vuln_found', 'blocked'],
            is_adaptive=True,
            adaptation_threshold=0.3,
            config={
                'rate_limit': 2,
                'payload_set': 'waf_bypass',
                'depth': 'normal'
            }
        )
    
    def _create_spa_fallback_strategy(self) -> Strategy:
        """创建 SPA Fallback 策略"""
        return Strategy(
            id='spa_fallback',
            name='SPA 深度分析策略',
            description='检测到 SPA fallback 行为时，深度分析 JS',
            priority=20,
            activation_conditions=[
                Condition(type='is_spa', operator='equals', value=True)
            ],
            actions=[
                Action(type='extract_js', priority=10),
                Action(type='analyze_webpack', priority=9),
                Action(type='find_api_urls', priority=9),
                Action(type='test_from_js', priority=8),
                Action(type='test_backend_direct', priority=7),
            ],
            execution_order='sequential',
            exit_on=['all_complete', 'api_found', 'timeout'],
            config={
                'rate_limit': 5,
                'js_depth': 3,
                'focus': 'reconnaissance'
            }
        )
    
    def _create_internal_address_strategy(self) -> Strategy:
        """创建内网地址策略"""
        return Strategy(
            id='internal_address',
            name='内网代理策略',
            description='发现内网地址时提示配置代理',
            priority=30,
            activation_conditions=[
                Condition(type='has_internal_ips', operator='equals', value=True)
            ],
            actions=[
                Action(type='mark_unreachable', priority=10),
                Action(type='extract_testable_apis', priority=9),
                Action(type='suggest_proxy', priority=8),
            ],
            execution_order='sequential',
            exit_on=['all_complete'],
            config={
                'rate_limit': 0,
                'requires_user_action': True
            }
        )
    
    def _create_high_value_endpoint_strategy(self) -> Strategy:
        """创建高价值端点策略"""
        return Strategy(
            id='high_value_endpoint',
            name='高价值端点深度测试',
            description='对高评分端点进行深度测试',
            priority=15,
            activation_conditions=[
                Condition(type='endpoint_score', operator='greater_than', value=7)
            ],
            actions=[
                Action(type='full_test_suite', priority=10),
                Action(type='test_edge_cases', priority=9),
                Action(type='bypass_auth', priority=8),
                Action(type='test_idor', priority=7),
            ],
            execution_order='sequential',
            exit_on=['all_complete', 'vuln_found'],
            is_adaptive=True,
            config={
                'rate_limit': 5,
                'depth': 'maximum',
                'timeout_multiplier': 2.0
            }
        )
    
    def _create_auth_testing_strategy(self) -> Strategy:
        """创建认证测试策略"""
        return Strategy(
            id='auth_testing',
            name='认证安全专项',
            description='针对认证接口的专项测试',
            priority=25,
            activation_conditions=[
                Condition(type='endpoint_type', operator='contains', value='auth'),
                Condition(type='endpoint_type', operator='contains', value='login'),
            ],
            actions=[
                Action(type='test_default_creds', priority=10),
                Action(type='test_auth_bypass', priority=9),
                Action(type='test_jwt', priority=9),
                Action(type='test_session', priority=8),
            ],
            execution_order='sequential',
            exit_on=['all_complete', 'vuln_found', 'locked'],
            is_adaptive=True,
            config={
                'rate_limit': 3,
                'safety_mode': True,
                'max_attempts': 5
            }
        )
    
    def _create_rate_limited_strategy(self) -> Strategy:
        """创建限速自适应策略"""
        return Strategy(
            id='rate_limited',
            name='限速自适应策略',
            description='检测到限速时自动降速',
            priority=40,
            activation_conditions=[
                Condition(type='network_status', operator='equals', value='rate_limited')
            ],
            actions=[
                Action(type='reduce_rate', priority=10),
                Action(type='rotate_user_agent', priority=9),
                Action(type='use_proxy', priority=8),
            ],
            execution_order='sequential',
            exit_on=['rate_restored', 'blocked'],
            config={
                'rate_limit': 1,
                'cooldown': 60,
                'backoff_factor': 0.5
            }
        )
    
    def _create_sensitive_operation_strategy(self) -> Strategy:
        """创建敏感操作策略"""
        return Strategy(
            id='sensitive_operation',
            name='敏感操作安全策略',
            description='测试敏感操作时使用最小化原则',
            priority=35,
            activation_conditions=[
                Condition(type='endpoint_type', operator='contains', value='pay'),
                Condition(type='endpoint_type', operator='contains', value='transfer'),
            ],
            actions=[
                Action(type='minimal_testing', priority=10),
                Action(type='simulate_normal_usage', priority=9),
                Action(type='avoid_destructive', priority=8),
            ],
            execution_order='sequential',
            exit_on=['all_complete'],
            config={
                'rate_limit': 1,
                'safety_mode': True,
                'require_confirmation': True
            }
        )
    
    def get_summary(self) -> Dict:
        """获取策略池摘要"""
        return {
            'total_strategies': len(self.strategies),
            'strategies': {
                k: v.to_dict() for k, v in self.strategies.items()
            }
        }


class Strategist:
    """
    策略师
    
    负责：
    - 创建策略计划
    - 评估策略有效性
    - 管理策略执行
    """
    
    def __init__(self, strategy_pool: Optional[StrategyPool] = None):
        self.strategy_pool = strategy_pool or StrategyPool()
        self.current_plan: Optional[StrategyPlan] = None
        self.execution_history: List[Dict] = []
    
    def create_strategy_plan(self, context: Dict, insights: List[Any] = None) -> StrategyPlan:
        """创建策略计划"""
        strategy_context = StrategyContext(context)
        self.current_plan = self.strategy_pool.create_plan(strategy_context, insights)
        
        return self.current_plan
    
    def evaluate_effectiveness(self, strategy: Strategy, results: Dict) -> float:
        """
        评估策略有效性
        
        基于：
        - 发现漏洞数量
        - 测试覆盖率
        - 执行时间
        - 误报率
        """
        vuln_count = results.get('vulnerabilities_found', 0)
        coverage = results.get('coverage', 0.0)
        execution_time = results.get('execution_time', 0.0)
        false_positive_rate = results.get('false_positive_rate', 0.0)
        
        vuln_weight = 0.4
        coverage_weight = 0.3
        time_weight = 0.1
        accuracy_weight = 0.2
        
        vuln_score = min(vuln_count / 10.0, 1.0)
        coverage_score = coverage
        time_score = 1.0 if execution_time < 300 else 0.5
        accuracy_score = 1.0 - false_positive_rate
        
        effectiveness = (
            vuln_score * vuln_weight +
            coverage_score * coverage_weight +
            time_score * time_weight +
            accuracy_score * accuracy_weight
        )
        
        return effectiveness
    
    def should_switch_strategy(self, current: Strategy, new: Strategy, feedback: Dict) -> bool:
        """判断是否应该切换策略"""
        effectiveness = feedback.get('effectiveness', 0.0)
        
        if effectiveness < current.adaptation_threshold:
            return True
        
        if current.state == StrategyState.FAILED:
            return True
        
        if current.should_exit(feedback.get('exit_reason', '')):
            return True
        
        return new.priority > current.priority
    
    def record_execution(self, strategy_id: str, results: Dict):
        """记录策略执行"""
        effectiveness = self.evaluate_effectiveness(
            self.strategy_pool.get_strategy(strategy_id) or Strategy(id=strategy_id, name=strategy_id, description=""),
            results
        )
        
        success = effectiveness > 0.3
        
        self.strategy_pool.record_outcome(strategy_id, success, effectiveness)
        
        self.execution_history.append({
            'strategy_id': strategy_id,
            'effectiveness': effectiveness,
            'success': success,
            'timestamp': datetime.now().isoformat(),
            'results': results
        })
    
    def get_best_strategy_for_context(self, context: StrategyContext) -> Strategy:
        """获取最佳策略"""
        return self.strategy_pool.select_strategy(context)
    
    def suggest_alternatives(self, context: StrategyContext) -> List[Strategy]:
        """建议备选策略"""
        return self.strategy_pool.select_multiple(context, max_strategies=3)


def create_strategy_pool() -> StrategyPool:
    """创建策略池工厂函数"""
    return StrategyPool()


def create_strategist(strategy_pool: Optional[StrategyPool] = None) -> Strategist:
    """创建策略师工厂函数"""
    return Strategist(strategy_pool)


if __name__ == "__main__":
    pool = create_strategy_pool()
    
    context = StrategyContext({
        'is_spa': True,
        'waf_detected': 'aliyun',
        'network_status': 'normal',
        'endpoint_score': 8,
        'tech_stack': {'vue', 'spring'},
        'insight_types': ['spa_fallback', 'waf_detected']
    })
    
    print("=" * 60)
    print("Strategy Pool Demo")
    print("=" * 60)
    
    selected = pool.select_strategy(context)
    print(f"\nSelected: {selected.name} ({selected.id})")
    print(f"Priority: {selected.priority}")
    print(f"Actions: {[a.type for a in selected.actions]}")
    print(f"Config: {selected.config}")
    
    print("\n" + "-" * 60)
    print("Alternative strategies for this context:")
    alternatives = pool.select_multiple(context, max_strategies=3)
    for i, s in enumerate(alternatives, 1):
        print(f"  {i}. {s.name} (priority: {s.priority})")
    
    print("\n" + "-" * 60)
    print("Strategy Pool Summary:")
    summary = pool.get_summary()
    print(f"Total strategies: {summary['total_strategies']}")
    for sid, sdata in summary['strategies'].items():
        print(f"  - {sid}: {sdata['name']} (state: {sdata['state']})")
