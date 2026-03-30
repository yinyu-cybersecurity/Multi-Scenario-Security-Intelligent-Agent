# innovator_agent.py - 头脑风暴兵
# 作用：当常规手段失效时，通过 RAG 检索历史 Writeups，调用 LLM 生成创新思路和临时规则
# 负责人：安全专家

import json
import sys
from typing import Dict, List
from state_v2 import CTFState
from config import config
from llm_client import llm_client
from logger import get_logger

logger = get_logger("Innovator")

# Optional: RAG functionality
try:
    from rag_builder.retriever import get_retriever
    RAG_AVAILABLE = True
except ImportError:
    get_retriever = None
    RAG_AVAILABLE = False

def get_innovator_prompt(features: dict, trace: list, rag_docs: list, focused_scene: str = None) -> str:
    """构建头脑风暴的 Prompt"""

    # 格式化 RAG 检索结果
    formatted_docs = ""
    for i, doc in enumerate(rag_docs):
        formatted_docs += f"--- 参考案例 {i+1} (相似度: {doc.get('similarity', 'N/A')}) ---\n"
        formatted_docs += f"{doc.get('content', '')[:1500]}\n\n" # 截断防止超长

    # 场景聚焦提示
    scene_hint = ""
    if focused_scene:
        scene_hint = f"""
⚠️ 已识别的目标场景: {focused_scene}
虽然常规攻击已失效，但该场景可能存在以下非常规攻击面：
- 历史CVE的变种绕过方式
- 配置错误导致的未授权访问
- 协议层面的漏洞利用
- 组件依赖链的漏洞

请优先考虑该场景相关的创新思路！
"""

    return f"""
你是一个顶级的 CTF 战队智囊（头脑风暴兵）。当前我们的常规攻击手段已经失效（失败分极高），我们需要你提供非常规的、创新的解题思路。

1. 当前环境信息
页面特征:
{json.dumps(features, indent=2, ensure_ascii=False)}

已失败的攻击尝试 (最近10次):
{json.dumps(trace, ensure_ascii=False)}
{scene_hint}
2. 知识库参考 (RAG 检索出的相似题目 Writeups)
⚠️ 注意：以下参考案例仅供参考，不一定适用于当前场景，请结合实际情况判断。
仔细阅读以下历史成功案例，寻找可以迁移到当前环境的技术：
{formatted_docs if formatted_docs else "无匹配的参考案例，请依靠你的内化知识。"}

3. 你的任务
1. 分析当前环境为什么常规攻击会失败（比如是否存在特定的 WAF，或者这是一个盲区）。
2. 结合知识库中的 Writeups，给出 1-3 个针对当前环境的临时探测/攻击规则。
3. 规则必须具体，例如："尝试 PHP filter chain 的 iconv 报错盲注"，或者 "使用 HTTP/2 单包并发绕过限制"。

4. 输出格式 (严格 JSON)
必须返回以下 JSON 格式：
{{
    "analysis": "常规SQLi失败，推测有深度WAF。根据参考案例，此框架常存在原型链污染...",
    "temp_rules": [
        {{
            "condition": "nodejs", // 适用的技术栈或特征
            "action": "prototype_pollution_rce", // 建议的攻击类型
            "confidence": 0.8, // 你对这个思路的信心
            "reason": "参考了 2024 年 XX 比赛的思路"
        }}
    ]
}}
"""

def innovator_node(state: CTFState) -> Dict:
    """
    [头脑风暴] (RAG增强 + LLM推理)
    """
    logger.info("Starting RAG brainstorming...")
    features = state.get("page_features", {})
    # [修复] 使用 attack_results 获取失败的攻击历史，而不是 success_trace
    # success_trace 只在找到flag后才填充，而 innovator 在攻击失败时调用
    attack_results = state.get("attack_results", [])
    # 提取攻击类型用于分析失败原因
    trace = [{"type": r.get("tool", "unknown"), "target": r.get("target", "")}
             for r in attack_results[-10:]] if attack_results else []
    focused_scene = state.get("focused_scene", "")

    # 1. 查询 RAG 知识库
    rag_results = []
    if RAG_AVAILABLE:
        logger.info("   Searching for similar Writeups...")
        try:
            retriever = get_retriever()
            rag_results = retriever.search_by_features(features, top_k=3)
            logger.info(f"   Found {len(rag_results)} highly relevant historical references")
        except Exception as e:
            logger.warning(f"   RAG search failed: {e}")
    else:
        logger.info("   RAG not available, proceeding without historical references")

    # 2. 构建 Prompt
    prompt = get_innovator_prompt(features, trace, rag_results, focused_scene)
    
    # 3. 调用 LLM
    logger.info("   🧠 LLM 正在进行创新推演...")
    response_text = llm_client.call_chat_completion(
        model=config.INNOVATOR_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7, # 头脑风暴需要更高的温度以发散思维
        json_mode=True
    )
    
    if not response_text:
        logger.warning("⚠️ LLM 调用失败，无法生成新规则")
        return {}

    # 4. 解析结果
    try:
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]
            
        result = json.loads(response_text)
        temp_rules = result.get("temp_rules", [])
        analysis = result.get("analysis", "")

        ok_icon = "✅" if (hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() in ('utf-8', 'utf8')) else "[OK]"
        logger.info(f"{ok_icon} 思考结论: {analysis[:100]}...")
        logger.info(f"{ok_icon} 生成了 {len(temp_rules)} 条临时规则")

        # AI过滤低质量规则
        if temp_rules and len(temp_rules) > 0:
            temp_rules = _ai_filter_rules(temp_rules, features)
            logger.info(f"   过滤后保留 {len(temp_rules)} 条有效规则")

        # 将 RAG 上下文简要保存，供后续追溯
        rag_context = [doc['metadata'].get('filename', 'Unknown WP') for doc in rag_results]
        
        return {
            "temp_rules": temp_rules,
            "rag_context": rag_context
        }
        
    except json.JSONDecodeError:
        fail_icon = "❌" if (hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() in ('utf-8', 'utf8')) else "[FAIL]"
        logger.warning(f"{fail_icon} JSON 解析失败: {response_text[:100]}...")
        return {}


def _ai_filter_rules(rules: List[Dict], features: Dict) -> List[Dict]:
    """
    AI过滤低质量规则

    过滤掉:
    1. 与当前环境不相关的规则
    2. 过于模糊的规则
    3. 置信度过低的规则

    Args:
        rules: 待过滤的规则列表
        features: 当前页面特征

    Returns:
        过滤后的规则列表
    """
    if not rules or len(rules) <= 1:
        return rules

    prompt = f"""评估这些攻击规则的质量，过滤掉无效规则。

规则列表:
{json.dumps(rules, ensure_ascii=False, indent=2)}

当前环境:
- 技术栈: {features.get('tech_stack', [])}
- 输入向量: {features.get('input_vectors', [])}

过滤标准:
1. 与当前环境完全不相关的规则
2. 过于模糊，没有具体技术细节的规则
3. 置信度低于0.5且没有明确理由的规则

输出JSON:
{{
    "filtered_rules": [保留的规则列表],
    "removed": [被移除的规则及原因]
}}"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if response:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            result = json.loads(response.strip())
            return result.get("filtered_rules", rules)

    except Exception as e:
        logger.warning(f"   AI过滤失败: {e}")

    return rules