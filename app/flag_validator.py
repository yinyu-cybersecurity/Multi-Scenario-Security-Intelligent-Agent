# flag_validator.py - AI驱动的flag验证
# 作用：验证发现的flag是否真实，避免将测试flag当成真flag

import re
import json
from typing import Tuple, List, Dict
from llm_client import llm_client
from config import config
from logger import get_logger

logger = get_logger(__name__)

# 常见假flag模式
FAKE_PATTERNS = [
    r'flag\{test\}',
    r'flag\{example\}',
    r'flag\{xxx+\}',
    r'flag\{your_flag_here\}',
    r'flag\{.*?placeholder.*?\}',
    r'flag\{.*?demo.*?\}',
    r'flag\{.*?sample.*?\}',
    r'flag\{\}',
]


def quick_fake_check(flag: str) -> bool:
    """快速检查是否是明显的假flag"""
    flag_lower = flag.lower()
    for pattern in FAKE_PATTERNS:
        if re.search(pattern, flag_lower, re.IGNORECASE):
            return True
    return False


def validate_flag(flag: str, context: Dict = None) -> Tuple[bool, str]:
    """
    AI验证flag真实性

    Args:
        flag: 待验证的flag
        context: 上下文信息，包含已知flag格式等

    Returns:
        (is_valid, reason) - 是否有效及原因
    """
    if not flag:
        return False, "flag为空"

    # 快速检查明显假flag
    if quick_fake_check(flag):
        return False, "明显的测试/示例flag"

    # 提取flag内容
    content_match = re.search(r'\{([^}]+)\}', flag)
    if not content_match:
        return False, "flag格式不正确"

    content = content_match.group(1)

    # 检查内容长度
    if len(content) < 8:
        return False, "flag内容过短"

    # 检查内容复杂度
    unique_chars = len(set(content))
    if unique_chars < 4:
        return False, "flag内容过于简单，疑似测试flag"

    # AI深度验证
    try:
        known_patterns = []
        if context:
            known_patterns = context.get('known_patterns', [])
            if not known_patterns and context.get('target_url'):
                # 从目标URL推断可能的比赛平台
                pass

        prompt = f"""判断这个flag是否是真实的CTF flag:

Flag: {flag}
已知平台格式: {known_patterns if known_patterns else '未知'}

假flag特征:
- 内容是简单单词如 test, example, demo, xxx
- 内容是提示性文字如 your_flag_here, placeholder
- 内容全是相同字符如 aaaaaaaa

真flag特征:
- 包含随机字符或哈希值
- 有一定长度和复杂度
- 符合比赛平台格式

只输出JSON: {{"valid": true/false, "reason": "简短理由"}}"""

        response = llm_client.call_chat_completion(
            model=config.HAIKU_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if response:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            result = json.loads(response.strip())
            return result.get("valid", True), result.get("reason", "")

    except Exception as e:
        logger.debug(f"AI验证flag失败: {e}")
        # AI验证失败时，基于基本检查通过
        return True, "AI验证失败，默认通过"

    return True, "基本检查通过"


def validate_flags(flags: List[str], context: Dict = None) -> List[Tuple[str, bool, str]]:
    """
    批量验证flags

    Returns:
        [(flag, is_valid, reason), ...]
    """
    results = []
    for flag in flags:
        is_valid, reason = validate_flag(flag, context)
        results.append((flag, is_valid, reason))
    return results


def filter_valid_flags(flags: List[str], context: Dict = None) -> List[str]:
    """过滤出有效的flags"""
    valid = []
    for flag in flags:
        is_valid, reason = validate_flag(flag, context)
        if is_valid:
            logger.info(f"验证flag有效: {flag[:30]}...")
            valid.append(flag)
        else:
            logger.warning(f"过滤假flag: {flag[:30]}... 原因: {reason}")
    return valid