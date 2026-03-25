# app/attack_strategy_evaluator.py
"""
攻击策略 AI 评估模块

功能:
- 评估攻击策略的成功概率
- 分析攻击路径的可行性
- 推荐最优攻击顺序
- 预测潜在风险

用途:
- 提升攻击决策质量
- 减少无效尝试
- 优化资源使用
"""
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from llm_client import llm_client
from config import config


@dataclass
class AttackStrategy:
    """攻击策略"""
    tool: str
    target: str
    vuln_type: str
    priority: int = 0
    estimated_success_rate: float = 0.0
    required_resources: List[str] = field(default_factory=list)
    risks: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """评估结果"""
    strategy: AttackStrategy
    score: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    reasoning: str
    recommendations: List[str] = field(default_factory=list)
    alternative_strategies: List[AttackStrategy] = field(default_factory=list)


class AttackStrategyEvaluator:
    """
    攻击策略 AI 评估器

    使用 LLM 评估攻击策略的可行性和成功率
    """

    def __init__(self):
        self.evaluation_history: List[EvaluationResult] = []

    def evaluate_strategy(
        self,
        strategy: AttackStrategy,
        context: Dict = None
    ) -> EvaluationResult:
        """
        评估单个攻击策略

        Args:
            strategy: 待评估的策略
            context: 额外上下文（目标信息、已有发现等）

        Returns:
            评估结果
        """
        context = context or {}

        prompt = f"""评估以下渗透测试攻击策略的成功概率和风险。

## 攻击策略
- 工具: {strategy.tool}
- 目标: {strategy.target}
- 漏洞类型: {strategy.vuln_type}

## 上下文
- 目标URL: {context.get('target_url', '未知')}
- 已发现的服务: {json.dumps(context.get('services', []), ensure_ascii=False)}
- 已发现的漏洞: {json.dumps(context.get('vulns', []), ensure_ascii=False)}
- 已获取的凭据: {context.get('credentials_count', 0)} 个
- 执行步数: {context.get('steps', 0)}

## 评估要求
1. 分析策略的可行性和成功概率
2. 识别潜在风险（检测、封禁、破坏性）
3. 推荐替代方案或优化建议
4. 给出置信度评估

## 输出格式 (JSON)
{{
  "score": 0.0-1.0,
  "confidence": 0.0-1.0,
  "reasoning": "评估理由",
  "risks": ["风险1", "风险2"],
  "recommendations": ["建议1", "建议2"],
  "alternative_strategies": [
    {{
      "tool": "替代工具",
      "target": "目标",
      "vuln_type": "漏洞类型",
      "priority": 1-10,
      "estimated_success_rate": 0.0-1.0
    }}
  ]
}}
"""

        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                json_mode=True
            )

            # 清理 markdown
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]

            result = json.loads(response.strip())

            evaluation = EvaluationResult(
                strategy=strategy,
                score=result.get("score", 0.5),
                confidence=result.get("confidence", 0.5),
                reasoning=result.get("reasoning", ""),
                recommendations=result.get("recommendations", []),
                alternative_strategies=[
                    AttackStrategy(**s) for s in result.get("alternative_strategies", [])
                ]
            )

            self.evaluation_history.append(evaluation)
            return evaluation

        except Exception as e:
            return EvaluationResult(
                strategy=strategy,
                score=0.5,
                confidence=0.0,
                reasoning=f"AI 评估失败: {str(e)}",
                recommendations=["继续执行当前策略"],
                alternative_strategies=[]
            )

    def evaluate_batch(
        self,
        strategies: List[AttackStrategy],
        context: Dict = None
    ) -> List[EvaluationResult]:
        """
        批量评估多个策略

        Args:
            strategies: 策略列表
            context: 上下文

        Returns:
            评估结果列表（按分数排序）
        """
        results = []

        # 单独评估每个策略
        for strategy in strategies:
            result = self.evaluate_strategy(strategy, context)
            results.append(result)

        # 按分数排序
        results.sort(key=lambda r: r.score, reverse=True)

        return results

    def recommend_order(
        self,
        strategies: List[AttackStrategy],
        context: Dict = None
    ) -> List[Tuple[AttackStrategy, float]]:
        """
        推荐攻击顺序

        Args:
            strategies: 候选策略列表
            context: 上下文

        Returns:
            [(strategy, score), ...] 按优先级排序
        """
        evaluations = self.evaluate_batch(strategies, context)

        return [
            (e.strategy, e.score)
            for e in evaluations
            if e.score > 0.3  # 过滤掉低分策略
        ]

    def analyze_attack_path(
        self,
        target: str,
        vulnerabilities: List[Dict],
        context: Dict = None
    ) -> Dict:
        """
        分析攻击路径

        Args:
            target: 目标
            vulnerabilities: 已发现的漏洞
            context: 上下文

        Returns:
            攻击路径分析结果
        """
        context = context or {}

        # 将漏洞转换为策略
        strategies = []
        for vuln in vulnerabilities:
            strategies.append(AttackStrategy(
                tool=self._recommend_tool(vuln.get("type", "")),
                target=target,
                vuln_type=vuln.get("type", "unknown"),
                priority=vuln.get("severity", 5)
            ))

        if not strategies:
            return {
                "recommendations": [],
                "best_path": None,
                "analysis": "未发现可利用的漏洞"
            }

        # 评估并排序
        evaluations = self.evaluate_batch(strategies, context)

        return {
            "recommendations": [
                {
                    "strategy": e.strategy.tool,
                    "target": e.strategy.target,
                    "score": e.score,
                    "reasoning": e.reasoning
                }
                for e in evaluations[:5]
            ],
            "best_path": {
                "tool": evaluations[0].strategy.tool,
                "target": evaluations[0].strategy.target,
                "score": evaluations[0].score
            } if evaluations else None,
            "analysis": self._generate_path_analysis(evaluations)
        }

    def _recommend_tool(self, vuln_type: str) -> str:
        """根据漏洞类型推荐工具"""
        tool_mapping = {
            "sqli": "sqlmap",
            "sql_injection": "sqlmap",
            "xss": "manual",
            "rce": "manual",
            "lfi": "manual",
            "rfi": "manual",
            "ssrf": "ssrf_scanner",
            "weak_password": "hydra",
            "brute_force": "hydra",
            "directory_traversal": "gobuster",
            "info_disclosure": "nuclei",
            "default_credentials": "hydra"
        }

        vuln_lower = vuln_type.lower()
        for key, tool in tool_mapping.items():
            if key in vuln_lower:
                return tool

        return "manual"

    def _generate_path_analysis(self, evaluations: List[EvaluationResult]) -> str:
        """生成路径分析摘要"""
        if not evaluations:
            return "无可用攻击路径"

        lines = [f"共评估 {len(evaluations)} 个攻击策略:"]

        for i, e in enumerate(evaluations[:5], 1):
            lines.append(
                f"  {i}. {e.strategy.tool} -> {e.strategy.vuln_type} "
                f"(得分: {e.score:.2f}, 置信度: {e.confidence:.2f})"
            )

        if evaluations[0].recommendations:
            lines.append("\n建议:")
            for rec in evaluations[0].recommendations[:3]:
                lines.append(f"  - {rec}")

        return "\n".join(lines)

    def get_statistics(self) -> Dict:
        """获取评估统计"""
        if not self.evaluation_history:
            return {
                "total_evaluations": 0,
                "avg_score": 0,
                "avg_confidence": 0
            }

        return {
            "total_evaluations": len(self.evaluation_history),
            "avg_score": sum(e.score for e in self.evaluation_history) / len(self.evaluation_history),
            "avg_confidence": sum(e.confidence for e in self.evaluation_history) / len(self.evaluation_history)
        }


# 全局评估器实例
_evaluator: Optional[AttackStrategyEvaluator] = None


def get_evaluator() -> AttackStrategyEvaluator:
    """获取全局评估器"""
    global _evaluator
    if _evaluator is None:
        _evaluator = AttackStrategyEvaluator()
    return _evaluator


def evaluate_attack_strategy(
    tool: str,
    target: str,
    vuln_type: str,
    context: Dict = None
) -> EvaluationResult:
    """便捷函数：评估攻击策略"""
    strategy = AttackStrategy(
        tool=tool,
        target=target,
        vuln_type=vuln_type
    )
    return get_evaluator().evaluate_strategy(strategy, context)