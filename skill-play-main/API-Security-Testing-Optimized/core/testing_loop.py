#!/usr/bin/env python3
"""
Insight-Driven Testing Loop - 洞察驱动测试循环

实现:
- 观察 → 推理 → 策略 → 执行 → 验证闭环
- 结果反馈机制
- 收敛检测
"""

import time
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Callable, Generator, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class LoopState(Enum):
    """循环状态"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    CONVERGED = "converged"
    BLOCKED = "blocked"
    COMPLETED = "completed"


@dataclass
class TestAction:
    """测试动作"""
    id: str
    type: str
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    
    priority: int = 0
    timeout: float = 30.0
    expected_outcome: Optional[str] = None
    
    executed_at: Optional[datetime] = None
    result: Optional[str] = None
    actual_outcome: Optional[str] = None


@dataclass
class ActionResult:
    """动作执行结果"""
    action: TestAction
    success: bool
    response_time: float
    
    status_code: Optional[int] = None
    content_length: int = 0
    content_preview: str = ""
    actual_outcome: Optional[str] = None
    
    deviation: float = 0.0
    new_insights: List[Any] = field(default_factory=list)
    
    error: Optional[str] = None


@dataclass
class Validation:
    """验证结果"""
    is_expected: bool
    deviation: float
    
    new_insights: List[Any] = field(default_factory=list)
    strategy_adjustment: Optional[Dict] = None
    
    confidence_impact: float = 0.0


@dataclass
class LoopProgress:
    """循环进度"""
    state: LoopState
    
    iterations: int = 0
    max_iterations: int = 100
    
    actions_executed: int = 0
    actions_total: int = 0
    
    insights_generated: int = 0
    vulnerabilities_found: int = 0
    
    convergence_score: float = 0.0
    effectiveness: float = 0.0
    
    elapsed_time: float = 0.0
    estimated_remaining: float = 0.0
    
    blockers: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


class Validator:
    """
    验证器
    
    职责：
    - 预期对比验证
    - 偏差计算
    - 新洞察生成
    """
    
    def __init__(self):
        self.validation_history: List[Validation] = []
        self.expected_outcomes: Dict[str, str] = {}
    
    def set_expected_outcome(self, action_id: str, outcome: str):
        """设置预期结果"""
        self.expected_outcomes[action_id] = outcome
    
    def validate_result(self, action: TestAction, result: ActionResult) -> Validation:
        """
        验证结果是否符合预期
        
        Args:
            action: 执行的动作
            result: 执行结果
        
        Returns:
            验证结果
        """
        expected = self.expected_outcomes.get(action.id, action.expected_outcome)
        
        if expected is None:
            return Validation(
                is_expected=True,
                deviation=0.0
            )
        
        is_expected = False
        deviation = 1.0
        
        if result.error:
            is_expected = expected == 'error'
            deviation = 1.0 if not is_expected else 0.0
        
        elif result.status_code:
            expected_codes = self._parse_expected_code(expected)
            is_expected = result.status_code in expected_codes
            
            if expected_codes:
                deviation = 0.0 if is_expected else 1.0
        
        elif result.content_preview:
            is_expected = self._check_content_match(expected, result.content_preview)
            deviation = 0.0 if is_expected else 0.5
        
        validation = Validation(
            is_expected=is_expected,
            deviation=deviation,
            confidence_impact=1.0 - deviation
        )
        
        self.validation_history.append(validation)
        
        return validation
    
    def _parse_expected_code(self, expected: str) -> Set[int]:
        """解析预期状态码"""
        codes = set()
        
        if '2xx' in expected or 'success' in expected.lower():
            codes.update([200, 201, 202, 204])
        elif '3xx' in expected or 'redirect' in expected.lower():
            codes.update([301, 302, 303, 307, 308])
        elif '4xx' in expected or 'client_error' in expected.lower():
            codes.update([400, 401, 403, 404])
        elif '5xx' in expected or 'server_error' in expected.lower():
            codes.update([500, 502, 503])
        else:
            try:
                codes.add(int(expected))
            except ValueError:
                pass
        
        return codes
    
    def _check_content_match(self, expected: str, content: str) -> bool:
        """检查内容匹配"""
        content_lower = content.lower()
        expected_lower = expected.lower()
        
        if expected_lower in content_lower:
            return True
        
        keywords = expected_lower.split()
        return any(kw in content_lower for kw in keywords)
    
    def check_convergence(self, recent_validations: List[Validation]) -> Tuple[bool, float]:
        """
        检查测试是否收敛
        
        Returns:
            (是否收敛, 收敛分数 0-1)
        """
        if len(recent_validations) < 3:
            return False, 0.0
        
        recent = recent_validations[-10:]
        
        deviations = [v.deviation for v in recent]
        avg_deviation = sum(deviations) / len(deviations)
        
        deviation_trend = 0.0
        if len(recent) >= 5:
            first_half = sum(deviations[:len(deviations)//2]) / (len(deviations)//2)
            second_half = sum(deviations[len(deviations)//2:]) / (len(deviations) - len(deviations)//2)
            deviation_trend = first_half - second_half
        
        convergence_score = 1.0 - avg_deviation
        
        if deviation_trend > 0.1:
            convergence_score *= 0.8
        
        is_converged = convergence_score > 0.8 and len(recent_validations) >= 5
        
        return is_converged, convergence_score
    
    def get_false_negative_risk(self) -> float:
        """
        评估假阴性风险
        
        Returns:
            风险分数 0-1 (越高风险越大)
        """
        if len(self.validation_history) < 3:
            return 0.3
        
        recent = self.validation_history[-10:]
        
        high_deviation_count = sum(1 for v in recent if v.deviation > 0.5)
        high_deviation_ratio = high_deviation_count / len(recent)
        
        consistent_no_finding = all(v.is_expected and v.deviation < 0.1 for v in recent[-5:])
        
        risk = high_deviation_ratio * 0.5
        
        if consistent_no_finding:
            risk += 0.3
        
        return min(risk, 1.0)
    
    def generate_validation_report(self) -> Dict:
        """生成验证报告"""
        recent = self.validation_history[-20:] if self.validation_history else []
        
        if not recent:
            return {
                'total_validations': 0,
                'convergence_score': 0.0,
                'false_negative_risk': 0.3,
                'recommendation': 'insufficient_data'
            }
        
        is_converged, convergence_score = self.check_convergence(recent)
        fn_risk = self.get_false_negative_risk()
        
        recommendations = []
        if fn_risk > 0.5:
            recommendations.append("假阴性风险较高，建议扩大测试范围")
        if convergence_score < 0.5:
            recommendations.append("收敛度低，可能存在遗漏")
        if is_converged:
            recommendations.append("测试已收敛，可以生成报告")
        
        return {
            'total_validations': len(self.validation_history),
            'recent_validations': len(recent),
            'expected_count': sum(1 for v in recent if v.is_expected),
            'unexpected_count': sum(1 for v in recent if not v.is_expected),
            'convergence_score': convergence_score,
            'is_converged': is_converged,
            'false_negative_risk': fn_risk,
            'recommendations': recommendations
        }


class InsightDrivenLoop:
    """
    洞察驱动测试循环
    
    实现：观察 → 推理 → 策略 → 执行 → 验证 闭环
    """
    
    def __init__(
        self,
        reasoner: Any,
        strategist: Any,
        context_manager: Any,
        executor: Optional[Callable] = None
    ):
        self.reasoner = reasoner
        self.strategist = strategist
        self.context_manager = context_manager
        self.executor = executor
        
        self.validator = Validator()
        
        self.state = LoopState.IDLE
        self.progress = LoopProgress(state=LoopState.IDLE)
        
        self.action_queue: List[TestAction] = []
        self.execution_history: List[ActionResult] = []
        
        self.callbacks: Dict[str, List[Callable]] = defaultdict(list)
    
    def on(self, event: str, callback: Callable):
        """注册回调"""
        self.callbacks[event].append(callback)
    
    def _emit(self, event: str, data: Any):
        """触发回调"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.warning(f"Callback error ({event}): {e}")
    
    def add_action(self, action: TestAction):
        """添加测试动作"""
        self.action_queue.append(action)
        self.action_queue.sort(key=lambda a: a.priority, reverse=True)
        self.progress.actions_total += 1
    
    def add_actions_batch(self, actions: List[TestAction]):
        """批量添加测试动作"""
        for action in actions:
            self.add_action(action)
    
    def run(
        self,
        max_iterations: int = 100,
        max_duration: float = 3600.0,
        convergence_threshold: float = 0.8
    ) -> Dict:
        """
        运行测试循环
        
        Args:
            max_iterations: 最大迭代次数
            max_duration: 最大运行时长（秒）
            convergence_threshold: 收敛阈值
        
        Returns:
            测试结果
        """
        self.state = LoopState.RUNNING
        self.progress = LoopProgress(
            state=LoopState.RUNNING,
            max_iterations=max_iterations
        )
        
        start_time = time.time()
        
        logger.info("Starting insight-driven testing loop")
        
        try:
            while self.state == LoopState.RUNNING:
                if self._should_terminate(max_iterations, max_duration):
                    break
                
                self._iterate()
                
                self.progress.elapsed_time = time.time() - start_time
                
                self._emit('iteration', self.progress)
        
        except Exception as e:
            logger.error(f"Loop error: {e}")
            self.state = LoopState.BLOCKED
            self.progress.blockers.append(str(e))
        
        finally:
            score = 0.0
            if self.state == LoopState.RUNNING:
                is_converged, score = self.validator.check_convergence(
                    self.validator.validation_history[-10:]
                )
                if is_converged:
                    self.state = LoopState.CONVERGED
                else:
                    self.state = LoopState.COMPLETED
            
            self.progress.state = self.state
            self.progress.convergence_score = score
        
        return self._generate_report()
    
    def _should_terminate(self, max_iterations: int, max_duration: float) -> bool:
        """检查是否应该终止"""
        if self.progress.iterations >= max_iterations:
            logger.info("Max iterations reached")
            return True
        
        if self.progress.elapsed_time >= max_duration:
            logger.info("Max duration reached")
            return True
        
        if self.progress.blockers:
            logger.warning(f"Blocked: {self.progress.blockers}")
            return True
        
        is_converged, _ = self.validator.check_convergence(
            self.validator.validation_history[-5:]
        )
        if is_converged:
            logger.info("Convergence achieved")
            return True
        
        return False
    
    def _iterate(self):
        """执行一次迭代"""
        self.progress.iterations += 1
        
        if not self.action_queue:
            if self.progress.insights_generated > 0:
                self._generate_more_actions()
            else:
                self.state = LoopState.COMPLETED
                return
        
        action = self.action_queue.pop(0)
        
        result = self._execute_action(action)
        
        self.execution_history.append(result)
        self.progress.actions_executed += 1
        
        validation = self.validator.validate_result(action, result)
        
        if not validation.is_expected:
            self._handle_unexpected_result(action, result, validation)
        
        insights = self._process_insights(result, validation)
        
        self.progress.insights_generated += len(insights)
        
        self._update_strategy(insights, result)
        
        self._emit('action_completed', {
            'action': action,
            'result': result,
            'validation': validation,
            'insights': insights
        })
    
    def _execute_action(self, action: TestAction) -> ActionResult:
        """执行动作"""
        action.executed_at = datetime.now()
        
        if self.executor:
            try:
                response = self.executor(action)
                
                return ActionResult(
                    action=action,
                    success=True,
                    response_time=response.get('time', 0.0),
                    status_code=response.get('status', 0),
                    content_length=len(response.get('content', '')),
                    content_preview=response.get('content', '')[:200]
                )
            
            except Exception as e:
                return ActionResult(
                    action=action,
                    success=False,
                    response_time=0.0,
                    error=str(e)
                )
        
        return ActionResult(
            action=action,
            success=False,
            response_time=0.0,
            error="No executor configured"
        )
    
    def _process_insights(self, result: ActionResult, validation: Validation) -> List[Any]:
        """处理洞察"""
        insights = list(validation.new_insights)
        
        if result.content_preview:
            response_data = {
                'url': result.action.target,
                'method': result.action.type,
                'status_code': result.status_code or 0,
                'content_type': '',
                'content': result.content_preview,
                'response_time': result.response_time
            }
            
            new_insights = self.reasoner.observe_and_reason(response_data)
            insights.extend(new_insights)
        
        return insights
    
    def _handle_unexpected_result(
        self, 
        action: TestAction, 
        result: ActionResult,
        validation: Validation
    ):
        """处理意外结果"""
        logger.info(f"Unexpected result for {action.type}: {result.actual_outcome}")
        
        if validation.deviation > 0.5:
            self.progress.suggestions.append(
                f"高偏差动作: {action.type} -> 考虑调整策略"
            )
    
    def _generate_more_actions(self):
        """生成更多测试动作"""
        if self.progress.insights_generated == 0:
            self.state = LoopState.COMPLETED
            return
        
        context = {
            'insights': self.reasoner.insight_store.get_active(),
            'endpoints': self.context_manager.context.discovered_endpoints,
            'phase': self.context_manager.context.current_phase.value
        }
        
        strategy = self.strategist.get_best_strategy_for_context(context)
        
        for action_def in strategy.actions:
            action = TestAction(
                id=f"generated_{int(time.time() * 1000)}",
                type=action_def.type,
                target="",
                params=action_def.params,
                priority=action_def.priority,
                timeout=action_def.timeout
            )
            self.add_action(action)
    
    def _update_strategy(self, insights: List[Any], result: ActionResult):
        """更新策略"""
        if not insights:
            return
        
        context = {
            'insights': insights,
            'result_success': result.success
        }
        
        try:
            self.strategist.record_execution(
                self.strategist.current_plan.primary_strategy.id if self.strategist.current_plan else 'unknown',
                {
                    'effectiveness': 1.0 - result.deviation if hasattr(result, 'deviation') else 0.5,
                    'vulnerabilities_found': self.progress.vulnerabilities_found
                }
            )
        except Exception as e:
            logger.warning(f"Strategy update error: {e}")
    
    def pause(self):
        """暂停循环"""
        self.state = LoopState.PAUSED
        self.progress.state = LoopState.PAUSED
    
    def resume(self):
        """恢复循环"""
        if self.state == LoopState.PAUSED:
            self.state = LoopState.RUNNING
    
    def stop(self):
        """停止循环"""
        self.state = LoopState.COMPLETED
        self.progress.state = LoopState.COMPLETED
    
    def get_progress(self) -> LoopProgress:
        """获取进度"""
        return self.progress
    
    def _generate_report(self) -> Dict:
        """生成报告"""
        validation_report = self.validator.generate_validation_report()
        
        return {
            'state': self.state.value,
            'progress': {
                'iterations': self.progress.iterations,
                'actions_executed': self.progress.actions_executed,
                'actions_total': self.progress.actions_total,
                'insights_generated': self.progress.insights_generated,
                'vulnerabilities_found': self.progress.vulnerabilities_found,
                'elapsed_time': self.progress.elapsed_time,
                'convergence_score': self.progress.convergence_score
            },
            'validation': validation_report,
            'blockers': self.progress.blockers,
            'suggestions': self.progress.suggestions
        }


def create_test_loop(
    reasoner: Any,
    strategist: Any,
    context_manager: Any,
    executor: Optional[Callable] = None
) -> InsightDrivenLoop:
    """创建测试循环工厂函数"""
    return InsightDrivenLoop(reasoner, strategist, context_manager, executor)


if __name__ == "__main__":
    from core.reasoning_engine import create_reasoner
    from core.strategy_pool import create_strategist
    from core.context_manager import create_context_manager
    
    reasoner = create_reasoner()
    strategist = create_strategist()
    context_manager = create_context_manager("http://example.com")
    
    loop = create_test_loop(reasoner, strategist, context_manager)
    
    loop.add_action(TestAction(
        id="test_1",
        type="GET",
        target="http://example.com/api",
        priority=10,
        expected_outcome="2xx"
    ))
    
    loop.add_action(TestAction(
        id="test_2",
        type="GET",
        target="http://example.com/login",
        priority=8,
        expected_outcome="html"
    ))
    
    print("Test loop initialized")
    print(f"Actions in queue: {len(loop.action_queue)}")
    
    report = loop.run(max_iterations=2)
    
    print("\nLoop Report:")
    print(f"State: {report['state']}")
    print(f"Iterations: {report['progress']['iterations']}")
    print(f"Actions executed: {report['progress']['actions_executed']}")
    print(f"Validation: {report['validation']}")
