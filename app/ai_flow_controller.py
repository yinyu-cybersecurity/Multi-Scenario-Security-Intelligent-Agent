# ai_flow_controller.py - AI自主流转控制器
#
# 作用：智能决定攻击流程的下一步走向
# 核心功能：
#   1. 立即触发器（无需AI判断）- FLAG/Shell/凭据/页面变化
#   2. AI分析场景 - 攻击有效性/策略切换/失败分累积
#   3. 决策链记录 - 最近10次决策，支持回溯分析
#
# 使用方式:
#     from ai_flow_controller import ai_flow_controller
#     decision = ai_flow_controller.decide(state, attack_result)
#

from enum import Enum
from typing import TypedDict, Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
import time
import json
import threading
from collections import deque

from logger import get_logger
from config import config
from llm_client import llm_client, safe_call_chat_completion
from router import RouteGuard, _route_guard, reset_route_guard

logger = get_logger("ai_flow_controller")


class FlowDecision(Enum):
    """流转决策类型"""
    CONTINUE_ATTACK = "continue_attack"  # 绕过verifier继续攻击（有shell/凭据/明显进展）
    GO_VERIFIER = "go_verifier"          # 正常流转到verifier
    REPORT_FLAG = "report_flag"          # 发现FLAG立即报告
    SWITCH_STRATEGY = "switch_strategy"  # 切换策略（失败多次）


class AttackEffectiveness(TypedDict):
    """攻击有效性评估结果"""
    is_effective: bool                   # 攻击是否有效
    progress_made: bool                  # 是否有进展
    confidence: float                    # 置信度 0-1
    reason: str                          # 判断理由
    suggested_next: str                  # 建议的下一步动作


@dataclass
class DecisionRecord:
    """决策记录"""
    timestamp: float                     # 决策时间戳
    decision: FlowDecision               # 决策类型
    trigger_type: str                    # 触发类型: "immediate" | "ai_analysis"
    state_snapshot: Dict                 # 状态快照（压缩版）
    attack_result: Optional[str]         # 攻击结果摘要
    reason: str                          # 决策理由
    confidence: float                    # 置信度


@dataclass
class FlowControllerConfig:
    """控制器配置"""
    # AI决策超时（秒）- 增加到60秒，网络请求可能较慢
    ai_decision_timeout: int = 60

    # 决策链最大长度
    max_decision_history: int = 10

    # 失败分阈值（从config读取）
    failure_score_for_explore: float = field(default_factory=lambda: config.FAILURE_SCORE_FOR_EXPLORE)
    failure_score_for_innovate: float = field(default_factory=lambda: config.FAILURE_SCORE_FOR_INNOVATE)
    failure_score_abandon: float = field(default_factory=lambda: config.FAILURE_SCORE_ABANDON)

    # 连续失败次数阈值（触发策略切换）
    consecutive_failures_threshold: int = 5

    # 页面变化检测阈值
    page_change_threshold: float = 0.3  # 页面相似度低于此值视为有明显变化

    # 是否启用AI分析
    enable_ai_analysis: bool = True


class AIFlowController:
    """
    AI自主流转控制器

    核心职责：
    1. 立即触发器检测 - 无需AI判断的明显成果
    2. AI分析决策 - 复杂场景的智能判断
    3. 决策链管理 - 记录和分析决策历史
    4. 熔断保护 - 防止AI决策超时或异常

    使用场景：
    - attacker节点执行后，决定下一步流向
    - 内网渗透场景下的流程控制
    - 多轮攻击后的策略调整
    """

    def __init__(self, cfg: Optional[FlowControllerConfig] = None):
        self.cfg = cfg or FlowControllerConfig()

        # 决策链历史
        self._decision_history: deque = deque(maxlen=self.cfg.max_decision_history)

        # 路由守卫（用于死循环检测）- 使用router模块的全局单例
        self._route_guard = _route_guard

        # 统计信息
        self._stats = {
            "total_decisions": 0,
            "immediate_decisions": 0,
            "ai_decisions": 0,
            "flag_found": 0,
            "shell_obtained": 0,
            "credentials_obtained": 0,
            "strategy_switches": 0,
        }

        # 线程锁保护决策链
        self._lock = threading.Lock()

    # =========================================================================
    # 核心决策方法
    # =========================================================================

    def decide(
        self,
        state: Dict,
        attack_result: Optional[Dict] = None,
        current_node: str = "attacker"
    ) -> Tuple[FlowDecision, str]:
        """
        决策下一步流向

        决策优先级：
        1. 立即触发器（无需AI）：
           - 发现FLAG → REPORT_FLAG
           - 获取Shell → CONTINUE_ATTACK（内网模式）
           - 获取凭据 → CONTINUE_ATTACK
           - 页面明显变化 → CONTINUE_ATTACK

        2. AI分析场景（需要LLM）：
           - 攻击是否有效但无直接成果
           - 是否需要切换策略
           - 失败分累积是否过高

        Args:
            state: 当前状态字典
            attack_result: 攻击执行结果（可选）
            current_node: 当前节点名（用于死循环检测）

        Returns:
            (FlowDecision, 决策理由)
        """
        with self._lock:
            self._stats["total_decisions"] += 1

            # 1. 立即触发器检测
            immediate_decision = self._check_immediate_triggers(state, attack_result)
            if immediate_decision:
                decision, reason = immediate_decision
                self._record_decision(
                    decision, "immediate", state,
                    self._summarize_attack_result(attack_result),
                    reason, 1.0  # 立即触发器置信度为1
                )
                self._stats["immediate_decisions"] += 1
                return decision, reason

            # 2. 检查失败分累积
            failure_decision = self._check_failure_score(state)
            if failure_decision:
                decision, reason = failure_decision
                self._record_decision(
                    decision, "immediate", state,
                    self._summarize_attack_result(attack_result),
                    reason, 0.9
                )
                self._stats["immediate_decisions"] += 1
                return decision, reason

            # 3. AI分析决策
            if self.cfg.enable_ai_analysis:
                ai_decision = self._ai_analyze(state, attack_result, current_node)
                if ai_decision:
                    decision, reason, confidence = ai_decision
                    self._record_decision(
                        decision, "ai_analysis", state,
                        self._summarize_attack_result(attack_result),
                        reason, confidence
                    )
                    self._stats["ai_decisions"] += 1
                    return decision, reason

            # 4. 降级决策：正常流转到verifier
            self._record_decision(
                FlowDecision.GO_VERIFIER, "fallback", state,
                self._summarize_attack_result(attack_result),
                "降级决策：无明显成果，正常流转", 0.5
            )
            return FlowDecision.GO_VERIFIER, "降级决策：正常流转到verifier"

    # =========================================================================
    # 立即触发器检测
    # =========================================================================

    def _check_immediate_triggers(
        self,
        state: Dict,
        attack_result: Optional[Dict]
    ) -> Optional[Tuple[FlowDecision, str]]:
        """
        检测立即触发器（无需AI判断）

        触发条件：
        1. 发现FLAG
        2. 获取Shell（内网模式）
        3. 获取凭据
        4. 页面明显变化

        Returns:
            (FlowDecision, 理由) 或 None
        """
        # 1. 检查FLAG发现
        found_flags = state.get("found_flags") or []
        if state.get("found_flag") or found_flags:
            flag_content = found_flags[-1] if found_flags else state.get("found_flag", "")
            self._stats["flag_found"] += 1
            logger.info(f"[FlowController] 发现FLAG: {flag_content[:50]}...")
            return FlowDecision.REPORT_FLAG, f"发现FLAG: {flag_content[:50]}"

        # 2. 检查Shell获取（内网模式）
        shell_session = state.get("shell_session")
        if shell_session and shell_session.get("session_id"):
            if state.get("internal_mode"):
                self._stats["shell_obtained"] += 1
                logger.info("[FlowController] 获取Shell会话，内网模式继续攻击")
                return FlowDecision.CONTINUE_ATTACK, "获取Shell，进入内网渗透流程"

        # 3. 检查凭据获取
        credentials = state.get("credentials") or []
        if credentials and len(credentials) > 0:
            # 检查是否有新凭据（对比上一次决策）
            last_cred_count = self._get_last_cred_count()
            if len(credentials) > last_cred_count:
                self._stats["credentials_obtained"] += 1
                new_cred = credentials[-1] if isinstance(credentials[-1], dict) else {}
                cred_desc = new_cred.get("username", "unknown") or str(new_cred)[:30]
                logger.info(f"[FlowController] 获取新凭据: {cred_desc}")
                return FlowDecision.CONTINUE_ATTACK, f"获取新凭据: {cred_desc}"

        # 4. 检查页面明显变化（从攻击结果判断）
        if attack_result:
            page_change = self._detect_page_change(attack_result)
            if page_change and page_change.get("significant"):
                logger.info(f"[FlowController] 页面明显变化: {page_change.get('description', '')[:50]}")
                return FlowDecision.CONTINUE_ATTACK, f"页面明显变化: {page_change.get('description', '')[:50]}"

        return None

    def _check_failure_score(self, state: Dict) -> Optional[Tuple[FlowDecision, str]]:
        """
        检查失败分累积

        逻辑：
        - 失败分达到 explore 阈值 → 进入探索模式（仍返回 GO_VERIFIER）
        - 失败分达到 innovate 阈值 → SWITCH_STRATEGY
        - 失败分达到 abandon 阈值 → 结束任务

        Returns:
            (FlowDecision, 理由) 或 None
        """
        failure_score = state.get("failure_weighted_score", 0.0)

        # 达到放弃阈值
        if failure_score >= self.cfg.failure_score_abandon:
            logger.warning(f"[FlowController] 失败分达到放弃阈值: {failure_score}")
            return FlowDecision.SWITCH_STRATEGY, f"失败分过高({failure_score}), 建议放弃或深度创新"

        # 达到创新阈值
        if failure_score >= self.cfg.failure_score_for_innovate:
            self._stats["strategy_switches"] += 1
            logger.info(f"[FlowController] 失败分达到创新阈值: {failure_score}")
            return FlowDecision.SWITCH_STRATEGY, f"失败分达到创新阈值({failure_score}), 切换策略"

        # 达到探索阈值 - 不切换策略，让 mode_manager 处理
        # 这里返回 None，让正常流转处理

        return None

    # =========================================================================
    # AI分析决策
    # =========================================================================

    def _ai_analyze(
        self,
        state: Dict,
        attack_result: Optional[Dict],
        current_node: str
    ) -> Optional[Tuple[FlowDecision, str, float]]:
        """
        AI分析攻击有效性

        分析场景：
        1. 攻击是否有效但无直接成果
        2. 是否需要切换策略
        3. 是否有潜在的突破口

        Returns:
            (FlowDecision, 理由, 置信度) 或 None（超时/异常）
        """
        # 构建分析上下文
        context = self._build_analysis_context(state, attack_result)

        prompt = f"""
分析攻击有效性并决定下一步流向。

## 当前状态摘要
- 当前URL: {context.get('current_url', 'N/A')}
- 访问页面数: {context.get('visited_pages', 0)}
- 漏洞候选项: {context.get('vuln_candidates', 0)}
- 失败分: {context.get('failure_score', 0.0)}
- 当前模式: {context.get('current_mode', 'exploit')}
- 内网模式: {context.get('internal_mode', False)}

## 最近攻击结果
{context.get('attack_summary', '无攻击结果')}

## 重要判断原则

### 优先使用GO_VERIFIER
当攻击结果为以下情况时，**必须**选择GO_VERIFIER进行验证：
- 结果显示"无有效信息"、"无攻击结果"、"请求失败"
- 状态码为403/404/500/超时
- 响应内容无明显变化或只有错误信息
- 无法确认攻击是否成功

### 使用CONTINUE_ATTACK的条件
**仅在明确满足以下条件之一时**才选择CONTINUE_ATTACK：
- 获取了Shell/凭据（检查state中shell_session/credentials）
- 页面内容有明显变化（如发现新路径、新内容）
- 响应中包含FLAG线索或敏感信息
- 攻击链有实质进展（不只是"有响应"）

### 使用SWITCH_STRATEGY的条件
- 连续多次攻击无效果
- 失败分累积超过阈值
- 当前策略已穷尽可能性

## 决策选项
1. GO_VERIFIER: 正常流转到verifier验证（推荐，除非有明确进展）
2. CONTINUE_ATTACK: 攻击有效，绕过verifier继续攻击
3. SWITCH_STRATEGY: 切换攻击策略

## 输出格式 (JSON)
```json
{{
    "decision": "CONTINUE_ATTACK|GO_VERIFIER|SWITCH_STRATEGY",
    "reason": "判断理由",
    "confidence": 0.0-1.0,
    "attack_effectiveness": {{
        "is_effective": true/false,
        "progress_made": true/false,
        "suggested_action": "建议的下一步动作"
    }}
}}
```
"""

        try:
            # 调用AI分析（带超时）
            response = safe_call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                timeout=self.cfg.ai_decision_timeout,
                temperature=0.1,
                json_mode=True
            )

            if not response:
                logger.warning("[FlowController] AI分析超时或失败")
                return None

            # 解析响应
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            result = json.loads(response.strip())
            decision_str = result.get("decision", "GO_VERIFIER")
            reason = result.get("reason", "")
            confidence = result.get("confidence", 0.5)

            # 转换决策
            decision_map = {
                "CONTINUE_ATTACK": FlowDecision.CONTINUE_ATTACK,
                "GO_VERIFIER": FlowDecision.GO_VERIFIER,
                "SWITCH_STRATEGY": FlowDecision.SWITCH_STRATEGY,
            }
            decision = decision_map.get(decision_str, FlowDecision.GO_VERIFIER)

            logger.info(f"[FlowController] AI决策: {decision.value} (置信度: {confidence})")

            return decision, reason, confidence

        except json.JSONDecodeError as e:
            logger.warning(f"[FlowController] AI响应解析失败: {e}")
            return None
        except Exception as e:
            logger.warning(f"[FlowController] AI分析异常: {e}")
            return None

    def _build_analysis_context(
        self,
        state: Dict,
        attack_result: Optional[Dict]
    ) -> Dict:
        """
        构建AI分析上下文（压缩版）

        提取关键信息，避免上下文膨胀
        """
        context = {
            "current_url": state.get("current_url", ""),
            "visited_pages": len(state.get("visited_fingerprints") or []),
            "vuln_candidates": len(state.get("vuln_candidates") or []),
            "failure_score": state.get("failure_weighted_score", 0.0),
            "current_mode": state.get("current_mode", "exploit"),
            "internal_mode": state.get("internal_mode", False),
            "attack_summary": self._summarize_attack_result(attack_result),
        }

        # 添加最近攻击结果
        attack_results = state.get("attack_results") or []
        if attack_results:
            recent = attack_results[-3:]  # 最近3条
            context["recent_results"] = [
                {"url": r.get("url", ""), "result": r.get("result", "")[:50]}
                for r in recent if isinstance(r, dict)
            ]

        return context

    # =========================================================================
    # 辅助方法
    # =========================================================================

    def _detect_page_change(self, attack_result: Dict) -> Optional[Dict]:
        """
        检测页面变化

        从攻击结果判断页面是否有明显变化
        """
        if not attack_result:
            return None

        # 检查响应状态
        status = attack_result.get("status_code", 200)
        if status >= 400:
            return None

        # 检查页面内容变化指示
        indicators = [
            attack_result.get("page_changed", False),
            attack_result.get("content_length_changed", False),
            attack_result.get("new_content_detected", False),
        ]

        if any(indicators):
            return {
                "significant": True,
                "description": attack_result.get("change_description", "页面内容变化")
            }

        # 检查是否有特定的成功指示
        if attack_result.get("success_indicator"):
            return {
                "significant": True,
                "description": attack_result.get("success_indicator", "")
            }

        return None

    def _summarize_attack_result(self, attack_result: Optional[Dict]) -> str:
        """压缩攻击结果摘要"""
        if not attack_result:
            return "无攻击结果"

        summary_parts = []

        if attack_result.get("action"):
            summary_parts.append(f"动作: {attack_result['action'][:30]}")

        if attack_result.get("status_code"):
            summary_parts.append(f"状态: {attack_result['status_code']}")

        if attack_result.get("result"):
            summary_parts.append(f"结果: {attack_result['result'][:50]}")

        if attack_result.get("error"):
            summary_parts.append(f"错误: {attack_result['error'][:30]}")

        return " | ".join(summary_parts) if summary_parts else "无有效信息"

    def _record_decision(
        self,
        decision: FlowDecision,
        trigger_type: str,
        state: Dict,
        attack_result: Optional[str],
        reason: str,
        confidence: float
    ):
        """记录决策到决策链"""
        record = DecisionRecord(
            timestamp=time.time(),
            decision=decision,
            trigger_type=trigger_type,
            state_snapshot=self._compress_state_snapshot(state),
            attack_result=attack_result,
            reason=reason,
            confidence=confidence
        )

        self._decision_history.append(record)

    def _compress_state_snapshot(self, state: Dict) -> Dict:
        """压缩状态快照，只保留关键信息"""
        return {
            "url": state.get("current_url", ""),
            "mode": state.get("current_mode", ""),
            "failure_score": state.get("failure_weighted_score", 0.0),
            "flags": len(state.get("found_flags") or []),
            "credentials": len(state.get("credentials") or []),
            "hosts": len(state.get("internal_hosts") or []),
        }

    def _get_last_cred_count(self) -> int:
        """获取上一次决策时的凭据数量"""
        if not self._decision_history:
            return 0

        last_record = self._decision_history[-1]
        return last_record.state_snapshot.get("credentials", 0)

    # =========================================================================
    # 决策链分析
    # =========================================================================

    def get_decision_history(self, limit: int = 10) -> List[Dict]:
        """
        获取决策历史

        Args:
            limit: 最大返回数量

        Returns:
            决策记录列表
        """
        with self._lock:
            history = list(self._decision_history)[-limit:]
            return [
                {
                    "timestamp": r.timestamp,
                    "decision": r.decision.value,
                    "trigger_type": r.trigger_type,
                    "state_snapshot": r.state_snapshot,
                    "attack_result": r.attack_result,
                    "reason": r.reason,
                    "confidence": r.confidence,
                }
                for r in history
            ]

    def analyze_decision_pattern(self) -> Dict:
        """
        分析决策模式

        用于诊断：
        - 是否频繁切换策略
        - 是否陷入死循环
        - AI决策成功率
        """
        with self._lock:
            if not self._decision_history:
                return {"analysis": "无决策历史"}

            history = list(self._decision_history)

            # 统计各决策类型次数
            decision_counts = {}
            for r in history:
                decision_counts[r.decision.value] = decision_counts.get(r.decision.value, 0) + 1

            # 检测重复模式（连续相同决策）
            consecutive_same = 0
            if len(history) >= 3:
                last_decisions = [r.decision for r in history[-3:]]
                if all(d == last_decisions[0] for d in last_decisions):
                    consecutive_same = 3

            # AI决策成功率
            ai_records = [r for r in history if r.trigger_type == "ai_analysis"]
            ai_avg_confidence = sum(r.confidence for r in ai_records) / len(ai_records) if ai_records else 0

            return {
                "total_decisions": len(history),
                "decision_distribution": decision_counts,
                "consecutive_same_count": consecutive_same,
                "ai_decision_count": len(ai_records),
                "ai_avg_confidence": ai_avg_confidence,
                "stats": self._stats,
                "recommendation": self._generate_recommendation(decision_counts, consecutive_same),
            }

    def _generate_recommendation(self, decision_counts: Dict, consecutive_same: int) -> str:
        """根据决策模式生成建议"""
        if consecutive_same >= 5:
            return "警告：连续相同决策过多，可能陷入死循环，建议人工干预"

        switch_count = decision_counts.get("switch_strategy", 0)
        if switch_count >= 3:
            return "提示：多次策略切换，建议检查攻击策略是否有效"

        if decision_counts.get("report_flag", 0) > 0:
            return "正常：已发现FLAG"

        if decision_counts.get("continue_attack", 0) >= 5:
            return "提示：连续继续攻击，请检查是否有实际进展"

        return "正常：决策模式无异常"

    def get_stats(self) -> Dict:
        """获取统计信息"""
        with self._lock:
            return {
                "stats": self._stats.copy(),
                "decision_history_length": len(self._decision_history),
            }

    def reset(self):
        """重置控制器状态（新任务开始时调用）"""
        with self._lock:
            self._decision_history.clear()
            reset_route_guard()  # 同步重置全局路由守卫
            self._stats = {
                "total_decisions": 0,
                "immediate_decisions": 0,
                "ai_decisions": 0,
                "flag_found": 0,
                "shell_obtained": 0,
                "credentials_obtained": 0,
                "strategy_switches": 0,
            }
        logger.info("[FlowController] 控制器已重置")


# =============================================================================
# 全局实例
# =============================================================================

# 单例实例
ai_flow_controller = AIFlowController()


def get_flow_controller() -> AIFlowController:
    """获取全局控制器实例"""
    return ai_flow_controller


def reset_flow_controller():
    """重置全局控制器（新任务开始时调用）"""
    ai_flow_controller.reset()


# =============================================================================
# 便捷函数
# =============================================================================

def decide_next_step(
    state: Dict,
    attack_result: Optional[Dict] = None,
    current_node: str = "attacker"
) -> Tuple[FlowDecision, str]:
    """
    便捷函数：决定下一步流向

    Args:
        state: 当前状态
        attack_result: 攻击结果
        current_node: 当前节点

    Returns:
        (FlowDecision, 理由)
    """
    return ai_flow_controller.decide(state, attack_result, current_node)


def is_continue_attack(state: Dict, attack_result: Optional[Dict] = None) -> bool:
    """
    便捷函数：判断是否应该继续攻击

    Returns:
        True if should continue attacking, False otherwise
    """
    decision, _ = ai_flow_controller.decide(state, attack_result)
    return decision == FlowDecision.CONTINUE_ATTACK


def should_report_flag(state: Dict) -> bool:
    """
    便捷函数：判断是否应该报告FLAG

    Returns:
        True if FLAG found and should report
    """
    found_flags = state.get("found_flags") or []
    return bool(state.get("found_flag") or found_flags)


def should_switch_strategy(state: Dict) -> bool:
    """
    便捷函数：判断是否应该切换策略

    Returns:
        True if failure score high enough to switch
    """
    failure_score = state.get("failure_weighted_score", 0.0)
    return failure_score >= config.FAILURE_SCORE_FOR_INNOVATE


# =============================================================================
# 内网模式专用判断
# =============================================================================

def decide_internal_flow(state: Dict, attack_result: Optional[Dict] = None) -> FlowDecision:
    """
    内网模式专用流转判断

    内网模式下的特殊逻辑：
    - Shell获取 → 继续内网攻击
    - 凭据获取 → 横向移动或凭据收集
    - Flag发现 → 继续攻陷其他主机

    Args:
        state: 当前状态
        attack_result: 攻击结果

    Returns:
        FlowDecision
    """
    decision, reason = ai_flow_controller.decide(state, attack_result, "internal_attacker")

    # 内网模式特殊处理
    if state.get("internal_mode"):
        # 如果发现FLAG但还有未攻陷主机，继续攻击
        if decision == FlowDecision.REPORT_FLAG:
            internal_hosts = state.get("internal_hosts") or []
            compromised = state.get("compromised_hosts") or []
            unexplored = len(internal_hosts) - len(compromised)

            if unexplored > 0:
                logger.info(f"[InternalFlow] 发现FLAG但还有{unexplored}台主机未攻陷，继续攻击")
                return FlowDecision.CONTINUE_ATTACK

        # Shell获取后继续攻击
        if decision == FlowDecision.CONTINUE_ATTACK:
            logger.info("[InternalFlow] 内网模式继续攻击")

    return decision