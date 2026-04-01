#!/usr/bin/env python3
"""
Agentic Orchestrator - 智能编排器 v3.0

集成组件:
- ReasoningEngine: 多层级推理引擎
- ContextManager: 上下文管理器
- StrategyPool: 策略池系统
- InsightDrivenLoop: 洞察驱动测试循环

核心理念：
1. 每个模块输出后，理解其含义
2. 根据当前状态，动态调整策略
3. 不是按顺序执行，而是按需执行
4. 失败时理解原因，而不是简单地继续
"""

import re
import time
import json
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from .reasoning_engine import (
        Reasoner, Insight, InsightType, UnderstandingLevel,
        Observation, Finding, InsightStore, create_reasoner
    )
    from .context_manager import (
        ContextManager, GlobalContext, TechStackContext,
        NetworkContext, SecurityContext, ContentContext,
        Endpoint, TestPhase, RateLimitStatus, ExposureLevel,
        DataClassification, create_context_manager
    )
    from .strategy_pool import (
        StrategyPool, Strategy, Strategist, StrategyContext,
        Action, Condition, StrategyState, create_strategy_pool, create_strategist
    )
    from .testing_loop import (
        InsightDrivenLoop, Validator, LoopState, TestAction,
        ActionResult, Validation, LoopProgress, create_test_loop
    )
except ImportError:
    from reasoning_engine import (
        Reasoner, Insight, InsightType, UnderstandingLevel,
        Observation, Finding, InsightStore, create_reasoner
    )
    from context_manager import (
        ContextManager, GlobalContext, TechStackContext,
        NetworkContext, SecurityContext, ContentContext,
        Endpoint, TestPhase, RateLimitStatus, ExposureLevel,
        DataClassification, create_context_manager
    )
    from strategy_pool import (
        StrategyPool, Strategy, Strategist, StrategyContext,
        Action, Condition, StrategyState, create_strategy_pool, create_strategist
    )
    from testing_loop import (
        InsightDrivenLoop, Validator, LoopState, TestAction,
        ActionResult, Validation, LoopProgress, create_test_loop
    )


logger = logging.getLogger(__name__)


class StageStatus(Enum):
    """阶段状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ADAPTED = "adapted"


@dataclass
class StageResult:
    """阶段结果"""
    name: str
    status: StageStatus
    duration: float = 0.0
    
    data: Any = None
    
    insights: List[Dict] = field(default_factory=list)
    
    problems: List[str] = field(default_factory=list)
    
    suggestions: List[str] = field(default_factory=list)
    
    next_stages: List[str] = field(default_factory=list)
    
    def summary(self) -> str:
        return f"{self.name}: {self.status.value} ({self.duration:.1f}s)"
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'status': self.status.value,
            'duration': self.duration,
            'insights': self.insights,
            'problems': self.problems,
            'suggestions': self.suggestions,
            'next_stages': self.next_stages
        }


class EnhancedAgenticOrchestrator:
    """
    增强型 Agentic Orchestrator v3.0
    
    集成组件：
    - ReasoningEngine: 多层级推理引擎
    - ContextManager: 上下文管理器
    - StrategyPool: 策略池系统
    - InsightDrivenLoop: 洞察驱动测试循环
    """
    
    def __init__(self, target: str, session: 'requests.Session' = None):
        self.target = target
        self.session = session or (requests.Session() if HAS_REQUESTS else None)
        
        self.reasoner = create_reasoner()
        self.context_manager = create_context_manager(target)
        self.strategy_pool = create_strategy_pool()
        self.strategist = create_strategist(self.strategy_pool)
        self.testing_loop: Optional[InsightDrivenLoop] = None
        
        self.stage_results: Dict[str, StageResult] = {}
        
        self.callbacks: Dict[str, List[Callable]] = {
            'stage_start': [],
            'stage_complete': [],
            'insight_generated': [],
            'strategy_changed': [],
            'blocker_detected': [],
            'vulnerability_found': [],
        }
        
        self._configure_callbacks()
    
    def _configure_callbacks(self):
        """配置内部回调"""
        
        def on_insight(insight_data):
            logger.info(f"Insight generated: {insight_data.get('content', '')[:50]}")
        
        def on_blocker(blocker_data):
            logger.warning(f"Blocker detected: {blocker_data}")
        
        def on_vuln(vuln_data):
            logger.info(f"Vulnerability found: {vuln_data}")
        
        self.callbacks['insight_generated'].append(on_insight)
        self.callbacks['blocker_detected'].append(on_blocker)
        self.callbacks['vulnerability_found'].append(on_vuln)
    
    def on(self, event: str, callback: Callable):
        """注册事件回调"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any):
        """触发事件"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.warning(f"Callback error for {event}: {e}")
    
    def execute(
        self,
        max_iterations: int = 100,
        max_duration: float = 3600.0,
        enable_fuzzing: bool = True,
        enable_testing: bool = True
    ) -> Dict:
        """
        执行增强型编排
        
        Args:
            max_iterations: 最大迭代次数
            max_duration: 最大运行时长（秒）
            enable_fuzzing: 是否启用 fuzzing
            enable_testing: 是否启用漏洞测试
        """
        print("=" * 70)
        print(" Enhanced Agentic Security Testing v3.0")
        print("=" * 70)
        print(f"Target: {self.target}")
        print(f"Components: Reasoner + ContextManager + StrategyPool + TestingLoop")
        print("=" * 70)
        
        start_time = time.time()
        
        self.context_manager.set_phase(TestPhase.RECON)
        
        self._stage_reconnaissance()
        
        self._stage_context_analysis()
        
        if self._has_blockers():
            self._handle_blockers()
            if self._should_abort():
                return self._generate_report(time.time() - start_time, "blocked")
        
        self._stage_discovery()
        
        self._stage_reasoning()
        
        if enable_fuzzing and not self._has_blockers():
            self._stage_fuzzing()
        else:
            self.stage_results['fuzzing'] = StageResult(
                name="fuzzing",
                status=StageStatus.SKIPPED,
                suggestions=["后端不可达，跳过 fuzzing"] if self._has_blockers() else []
            )
        
        if enable_testing and not self._has_blockers():
            self._stage_testing()
        else:
            self.stage_results['testing'] = StageResult(
                name="testing",
                status=StageStatus.SKIPPED,
                suggestions=["后端不可达，跳过测试"] if self._has_blockers() else []
            )
        
        duration = time.time() - start_time
        
        return self._generate_report(duration)
    
    def _stage_reconnaissance(self):
        """阶段 1: 侦察"""
        print("\n[*] Phase 1: 侦察")
        
        self._emit('stage_start', {'stage': 'reconnaissance'})
        start = time.time()
        
        test_urls = [
            self.target,
            f"{self.target}/login",
            f"{self.target}/admin",
            f"{self.target}/api",
            f"{self.target}/api-docs",
            f"{self.target}/swagger.json",
        ]
        
        for url in test_urls:
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                
                response_data = {
                    'url': url,
                    'method': 'GET',
                    'status_code': resp.status_code,
                    'content_type': resp.headers.get('Content-Type', ''),
                    'content': resp.text[:1000],
                    'headers': dict(resp.headers),
                    'response_time': resp.elapsed.total_seconds(),
                    'source': 'recon'
                }
                
                insights = self.reasoner.observe_and_reason(response_data)
                
                for insight in insights:
                    self._process_insight(insight)
                
                self.context_manager.update_network_status(True)
                self.context_manager.update_network_status(
                    True, 
                    reason=f"{resp.status_code} from {url}"
                )
                
                if 'tech_fingerprints' in response_data:
                    pass
                
            except Exception as e:
                logger.warning(f"Recon error for {url}: {e}")
                self.context_manager.update_network_status(False, reason=str(e))
        
        duration = time.time() - start
        
        insights_data = [i.to_dict() for i in self.reasoner.insight_store.get_active()]
        
        self.stage_results['reconnaissance'] = StageResult(
            name="reconnaissance",
            status=StageStatus.COMPLETED,
            duration=duration,
            insights=insights_data
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    观察数: {len(self.reasoner.get_observations())}")
        print(f"    洞察数: {len(insights_data)}")
        
        self._emit('stage_complete', {'stage': 'reconnaissance', 'duration': duration})
    
    def _stage_context_analysis(self):
        """阶段 2: 上下文分析"""
        print("\n[*] Phase 2: 上下文分析")
        
        self._emit('stage_start', {'stage': 'context_analysis'})
        start = time.time()
        
        for obs in self.reasoner.get_observations()[-10:]:
            if obs.tech_fingerprints:
                self.context_manager.update_tech_stack(obs.tech_fingerprints)
            
            if obs.spa_indicators:
                self.context_manager.set_spa_mode(True)
            
            if obs.api_indicators:
                for url in obs.url:
                    if 'swagger' in url.lower() or 'api-docs' in url.lower():
                        self.context_manager.add_swagger_url(url)
            
            if obs.security_indicators:
                if any('error' in ind for ind in obs.security_indicators):
                    self.context_manager.add_error_leak('|'.join(obs.security_indicators))
        
        duration = time.time() - start
        
        context_summary = self.context_manager.get_summary()
        
        self.stage_results['context_analysis'] = StageResult(
            name="context_analysis",
            status=StageStatus.COMPLETED,
            duration=duration,
            data=context_summary,
            insights=[{
                'type': 'context_summary',
                'content': f"技术栈: {context_summary.get('tech_stack', {})}"
            }]
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    技术栈: {context_summary.get('tech_stack', {})}")
        print(f"    SPA: {context_summary.get('content', {}).get('is_spa', False)}")
        
        self._emit('stage_complete', {'stage': 'context_analysis'})
    
    def _stage_discovery(self):
        """阶段 3: API 发现"""
        print("\n[*] Phase 3: API 发现")
        
        self._emit('stage_start', {'stage': 'discovery'})
        start = time.time()
        
        discovered_paths = set()
        
        for obs in self.reasoner.get_observations():
            if obs.api_indicators:
                discovered_paths.add(obs.url)
        
        for path in discovered_paths:
            endpoint = Endpoint(
                path=path,
                method='GET',
                source='reasoning',
                score=5
            )
            self.context_manager.add_discovered_endpoint(endpoint)
        
        if self.context_manager.context.content.swagger_urls:
            for url in self.context_manager.context.content.swagger_urls:
                endpoint = Endpoint(
                    path=url,
                    method='GET',
                    source='swagger',
                    score=8,
                    is_high_value=True
                )
                self.context_manager.add_discovered_endpoint(endpoint)
        
        duration = time.time() - start
        
        self.stage_results['discovery'] = StageResult(
            name="discovery",
            status=StageStatus.COMPLETED,
            duration=duration,
            data={
                'total_endpoints': len(self.context_manager.context.discovered_endpoints),
                'high_value': len(self.context_manager.get_high_value_endpoints())
            }
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    发现端点: {len(self.context_manager.context.discovered_endpoints)}")
        
        self._emit('stage_complete', {'stage': 'discovery'})
    
    def _stage_reasoning(self):
        """阶段 4: 推理分析"""
        print("\n[*] Phase 4: 推理分析")
        
        self._emit('stage_start', {'stage': 'reasoning'})
        start = time.time()
        
        insights = self.reasoner.insight_store.get_active()
        
        for insight in insights:
            if insight.type == InsightType.BLOCKER:
                self._emit('blocker_detected', insight.to_dict())
            
            if insight.findings:
                for finding in insight.findings:
                    if 'strategy' in finding.strategy:
                        pass
        
        context = StrategyContext({
            'insights': insights,
            'tech_stack': self.context_manager.context.tech_stack.to_dict(),
            'network_status': self.context_manager.context.network.rate_limit_status.value,
            'is_spa': self.context_manager.context.content.is_spa,
            'has_internal_ips': bool(self.context_manager.context.content.internal_ips),
            'waf_detected': self.context_manager.context.tech_stack.waf
        })
        
        selected_strategy = self.strategy_pool.select_strategy(context, insights)
        
        self.strategist.current_plan = self.strategist.create_strategy_plan(context, insights)
        
        duration = time.time() - start
        
        self.stage_results['reasoning'] = StageResult(
            name="reasoning",
            status=StageStatus.COMPLETED,
            duration=duration,
            data={
                'strategy_selected': selected_strategy.id,
                'strategy_name': selected_strategy.name,
                'insights_count': len(insights)
            },
            insights=[i.to_dict() for i in insights]
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    选择策略: {selected_strategy.name} ({selected_strategy.id})")
        
        self._emit('stage_complete', {'stage': 'reasoning'})
    
    def _stage_fuzzing(self):
        """阶段 5: 智能 Fuzzing"""
        print("\n[*] Phase 5: 智能 Fuzzing")
        
        self._emit('stage_start', {'stage': 'fuzzing'})
        start = time.time()
        
        print("    使用增强型推理引擎进行智能 Fuzzing")
        
        fuzz_targets = []
        
        for endpoint in self.context_manager.get_high_value_endpoints():
            full_url = f"{self.target}{endpoint.path}"
            fuzz_targets.append({
                'url': full_url,
                'method': endpoint.method,
                'score': endpoint.score
            })
        
        fuzz_results = []
        
        for target in fuzz_targets[:20]:
            try:
                resp = self.session.get(
                    target['url'],
                    timeout=5,
                    allow_redirects=False
                )
                
                fuzz_results.append({
                    'url': target['url'],
                    'status': resp.status_code,
                    'length': len(resp.content)
                })
                
                response_data = {
                    'url': target['url'],
                    'method': 'GET',
                    'status_code': resp.status_code,
                    'content_type': resp.headers.get('Content-Type', ''),
                    'content': resp.text[:500],
                    'response_time': resp.elapsed.total_seconds(),
                    'source': 'fuzzing'
                }
                
                insights = self.reasoner.observe_and_reason(response_data)
                for insight in insights:
                    self._process_insight(insight)
                
            except Exception as e:
                logger.debug(f"Fuzz error for {target['url']}: {e}")
        
        duration = time.time() - start
        
        alive_count = sum(1 for r in fuzz_results if r['status'] < 500)
        
        self.stage_results['fuzzing'] = StageResult(
            name="fuzzing",
            status=StageStatus.COMPLETED,
            duration=duration,
            data={
                'targets_tested': len(fuzz_targets),
                'alive': alive_count,
                'results': fuzz_results[:10]
            }
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    测试目标: {len(fuzz_targets)}, 存活: {alive_count}")
        
        self._emit('stage_complete', {'stage': 'fuzzing'})
    
    def _stage_testing(self):
        """阶段 6: 漏洞测试"""
        print("\n[*] Phase 6: 漏洞测试")
        
        self._emit('stage_start', {'stage': 'testing'})
        start = time.time()
        
        print("    使用洞察驱动循环进行漏洞测试")
        
        if self.testing_loop is None:
            self.testing_loop = create_test_loop(
                self.reasoner,
                self.strategist,
                self.context_manager,
                executor=self._create_executor()
            )
        
        for endpoint in self.context_manager.get_high_value_endpoints()[:5]:
            self.testing_loop.add_action(TestAction(
                id=f"test_{endpoint.path}",
                type='GET',
                target=f"{self.target}{endpoint.path}",
                priority=endpoint.score,
                expected_outcome='2xx'
            ))
        
        report = self.testing_loop.run(max_iterations=20)
        
        duration = time.time() - start
        
        self.stage_results['testing'] = StageResult(
            name="testing",
            status=StageStatus.COMPLETED if report['state'] != 'blocked' else StageStatus.FAILED,
            duration=duration,
            data=report,
            insights=[report]
        )
        
        print(f"    完成 ({duration:.1f}s)")
        print(f"    状态: {report['state']}")
        print(f"    漏洞发现: {report['progress'].get('vulnerabilities_found', 0)}")
        
        self._emit('stage_complete', {'stage': 'testing'})
    
    def _create_executor(self) -> Callable:
        """创建执行器"""
        def execute(action: TestAction) -> Dict:
            try:
                resp = self.session.request(
                    action.type,
                    action.target,
                    timeout=action.timeout,
                    allow_redirects=False
                )
                
                return {
                    'status': resp.status_code,
                    'content': resp.text[:500],
                    'time': resp.elapsed.total_seconds(),
                    'headers': dict(resp.headers)
                }
            except Exception as e:
                return {
                    'status': 0,
                    'content': '',
                    'time': 0,
                    'error': str(e)
                }
        
        return execute
    
    def _process_insight(self, insight: Insight):
        """处理洞察"""
        self._emit('insight_generated', insight.to_dict())
        
        if insight.type == InsightType.BLOCKER:
            self._emit('blocker_detected', insight.to_dict())
        
        if insight.type.value == 'opportunity' and 'swagger' in insight.content.lower():
            for finding in insight.findings:
                if finding.evidence:
                    self.context_manager.add_swagger_url(finding.evidence[0])
    
    def _has_blockers(self) -> bool:
        """是否有阻碍因素"""
        blockers = self.reasoner.insight_store.get_by_type(InsightType.BLOCKER)
        return len(blockers) > 0
    
    def _should_abort(self) -> bool:
        """是否应该中止"""
        if self.context_manager.is_rate_limited():
            return True
        
        internal_ips = self.context_manager.get_internal_addresses()
        if internal_ips and not self.context_manager.context.network.requires_proxy:
            return True
        
        return False
    
    def _handle_blockers(self):
        """处理阻碍因素"""
        blockers = self.reasoner.insight_store.get_by_type(InsightType.BLOCKER)
        
        print(f"\n[!] 发现 {len(blockers)} 个阻碍因素:")
        for blocker in blockers:
            print(f"    - {blocker.content}")
            
            for finding in blocker.findings:
                if finding.strategy:
                    print(f"      建议: {finding.strategy[:100]}...")
    
    def _generate_report(self, duration: float, early_termination: Optional[str] = None) -> Dict:
        """生成报告"""
        print("\n" + "=" * 70)
        print(" Enhanced Agentic Analysis Report v3.0")
        print("=" * 70)
        
        print(f"\n执行时间: {duration:.1f}s")
        print(f"目标: {self.target}")
        
        if early_termination:
            print(f"提前终止: {early_termination}")
        
        print(f"\n组件状态:")
        print(f"  - Reasoner: {len(self.reasoner.insight_store.get_active())} 活跃洞察")
        print(f"  - ContextManager: {len(self.context_manager.context.discovered_endpoints)} 端点")
        print(f"  - StrategyPool: {len(self.strategy_pool.get_all_strategies())} 策略")
        
        insights = self.reasoner.insight_store.get_active()
        
        if insights:
            print(f"\n洞察 ({len(insights)} 个):")
            for i, insight in enumerate(insights[:10], 1):
                icon = {
                    InsightType.OBSERVATION: "[O]",
                    InsightType.PATTERN: "[P]",
                    InsightType.INFERENCE: "[I]",
                    InsightType.BLOCKER: "[X]",
                    InsightType.OPPORTUNITY: "[*]",
                    InsightType.STRATEGY_CHANGE: "[S]",
                }.get(insight.type, "[-]")
                
                print(f"  {icon} {insight.content[:70]}...")
        
        blockers = self.reasoner.insight_store.get_by_type(InsightType.BLOCKER)
        if blockers:
            print(f"\n阻碍因素 ({len(blockers)}):")
            for b in blockers:
                print(f"  [X] {b.content}")
        
        opportunities = self.reasoner.insight_store.get_by_type(InsightType.OPPORTUNITY)
        if opportunities:
            print(f"\n机会 ({len(opportunities)}):")
            for o in opportunities:
                print(f"  [*] {o.content}")
        
        print(f"\n上下文摘要:")
        summary = self.context_manager.get_summary()
        print(f"  技术栈: {summary.get('tech_stack', {})}")
        print(f"  网络: {summary.get('network', {})}")
        print(f"  SPA: {summary.get('content', {}).get('is_spa', False)}")
        print(f"  API文档: {summary.get('content', {}).get('has_api_docs', False)}")
        
        print("\n" + "=" * 70)
        
        return {
            'target': self.target,
            'duration': duration,
            'early_termination': early_termination,
            'components': {
                'reasoner': {
                    'total_insights': len(self.reasoner.insight_store.insights),
                    'active_insights': len(self.reasoner.insight_store.get_active())
                },
                'context_manager': summary,
                'strategy_pool': {
                    'strategies': len(self.strategy_pool.get_all_strategies()),
                    'selected': self.strategist.current_plan.primary_strategy.id if self.strategist.current_plan else None
                }
            },
            'stage_results': {k: v.to_dict() for k, v in self.stage_results.items()},
            'insights': [i.to_dict() for i in insights],
            'blockers': [b.to_dict() for b in blockers],
            'opportunities': [o.to_dict() for o in opportunities]
        }
    
    def get_context(self) -> Dict:
        """获取当前上下文"""
        return self.context_manager.export_context()
    
    def get_insights(self) -> List[Dict]:
        """获取所有洞察"""
        return [i.to_dict() for i in self.reasoner.insight_store.insights]
    
    def save_state(self, filepath: str):
        """保存状态"""
        state = {
            'target': self.target,
            'context': self.context_manager.export_context(),
            'insights': self.get_insights(),
            'stage_results': {k: v.to_dict() for k, v in self.stage_results.items()}
        }
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2, default=str)
    
    @classmethod
    def load_state(cls, filepath: str) -> 'EnhancedAgenticOrchestrator':
        """加载状态"""
        with open(filepath, 'r') as f:
            state = json.load(f)
        
        orchestrator = cls(state['target'])
        
        return orchestrator


def run_enhanced_agentic_test(
    target: str,
    max_iterations: int = 100,
    max_duration: float = 3600.0
) -> Dict:
    """运行增强型 Agentic 测试"""
    orchestrator = EnhancedAgenticOrchestrator(target)
    return orchestrator.execute(
        max_iterations=max_iterations,
        max_duration=max_duration
    )


if __name__ == "__main__":
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    
    result = run_enhanced_agentic_test(target, max_iterations=20)
    
    print("\n[JSON Output]")
    print(json.dumps(result, indent=2, default=str))
