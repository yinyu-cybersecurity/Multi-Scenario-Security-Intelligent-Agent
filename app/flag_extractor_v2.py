#!/usr/bin/env python
"""
AI驱动的Flag提取器
用AI分析替代硬编码正则，支持任意CTF平台
"""

import re
import base64
import json
from typing import List, Optional, Tuple, Any, Callable
from dataclasses import dataclass


@dataclass
class FlagCandidate:
    """Flag候选项"""
    value: str
    confidence: float  # 0.0 - 1.0
    source: str  # 发现来源
    reasoning: str  # AI的判断理由


class AIFlagExtractor:
    """
    AI驱动的Flag提取器

    核心思路：
    1. 最小化的硬编码规则（仅用于快速预过滤）
    2. AI分析内容识别Flag
    3. 支持AI生成提取脚本处理复杂场景
    """

    # 最小化预过滤规则（仅用于快速判断，不依赖特定平台）
    PRE_FILTER = re.compile(r'[a-zA-Z0-9_]+\{[^\}]{5,100}\}')

    # 常见编码检测（轻量级）
    ENCODING_HINTS = {
        'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
        'hex': re.compile(r'\b[0-9A-Fa-f]{40,}\b'),
        'unicode': re.compile(r'\\u[0-9A-Fa-f]{4}'),
    }

    def __init__(self, ai_client: Any = None, execute_script: bool = True):
        """
        Args:
            ai_client: AI客户端（需支持generate/prompt方法）
            execute_script: 是否允许执行AI生成的提取脚本
        """
        self.ai_client = ai_client
        self.execute_script = execute_script
        self._script_executor = None

    def extract(
        self,
        text: str,
        context: str = "",
        max_candidates: int = 5
    ) -> List[FlagCandidate]:
        """
        智能提取Flag

        Args:
            text: 要分析的文本
            context: 额外上下文（如题目描述、提示等）
            max_candidates: 最大返回候选项数

        Returns:
            Flag候选项列表，按置信度排序
        """
        candidates = []
        seen_values = set()

        # 1. 快速预过滤 - 找出可能的Flag位置
        pre_filtered = self._pre_filter(text)

        # 2. 尝试解码编码内容
        decoded_content = self._try_decode(text)

        # 3. AI分析
        if self.ai_client:
            ai_candidates = self._ai_analyze(text, decoded_content, context)
            for c in ai_candidates:
                if c.value not in seen_values:
                    candidates.append(c)
                    seen_values.add(c.value)

        # 4. 备用：基于规则的简单提取（无AI时）
        if not candidates:
            for match, source in pre_filtered:
                if match not in seen_values:
                    candidates.append(FlagCandidate(
                        value=match,
                        confidence=0.6,
                        source=f"rule:{source}",
                        reasoning="匹配通用Flag模式"
                    ))
                    seen_values.add(match)

        # 排序并限制数量
        candidates.sort(key=lambda x: x.confidence, reverse=True)
        return candidates[:max_candidates]

    def _pre_filter(self, text: str) -> List[Tuple[str, str]]:
        """快速预过滤，找出可能的Flag"""
        results = []

        # 通用模式
        matches = self.PRE_FILTER.findall(text)
        for m in matches:
            results.append((m, "universal"))

        return results

    def _try_decode(self, text: str) -> List[Tuple[str, str, str]]:
        """
        尝试解码编码内容
        Returns: [(解码后内容, 编码类型, 原始片段), ...]
        """
        decoded = []

        # Base64
        for match in self.ENCODING_HINTS['base64'].findall(text):
            try:
                padding = 4 - len(match) % 4
                if padding != 4:
                    match += '=' * padding
                result = base64.b64decode(match).decode('utf-8', errors='ignore')
                if result and len(result) > 5:
                    decoded.append((result, 'base64', match))
            except:
                pass

        # Hex
        for match in self.ENCODING_HINTS['hex'].findall(text):
            try:
                result = bytes.fromhex(match).decode('utf-8', errors='ignore')
                if result and len(result) > 5:
                    decoded.append((result, 'hex', match))
            except:
                pass

        # Unicode
        if self.ENCODING_HINTS['unicode'].search(text):
            try:
                result = text.encode('utf-8').decode('unicode_escape')
                decoded.append((result, 'unicode', 'full'))
            except:
                pass

        return decoded

    def _ai_analyze(
        self,
        text: str,
        decoded_content: List[Tuple[str, str, str]],
        context: str
    ) -> List[FlagCandidate]:
        """
        AI分析文本识别Flag

        这个方法应该由具体的AI客户端实现
        """
        candidates = []

        # 构建提示
        prompt = self._build_analysis_prompt(text, decoded_content, context)

        try:
            # 调用AI分析
            if hasattr(self.ai_client, 'generate'):
                response = self.ai_client.generate(prompt)
            elif hasattr(self.ai_client, 'invoke'):
                response = self.ai_client.invoke(prompt)
            else:
                return candidates

            # 解析AI响应
            candidates = self._parse_ai_response(response)

        except Exception as e:
            pass

        return candidates

    def _build_analysis_prompt(
        self,
        text: str,
        decoded_content: List[Tuple[str, str, str]],
        context: str
    ) -> str:
        """构建AI分析提示"""
        prompt = """你是一个CTF Flag识别专家。分析以下内容，找出所有可能的Flag。

规则：
1. Flag通常格式为: prefix{content}，如 flag{xxx}, ctf{xxx}, NSSCTF{xxx} 等
2. 也可能是不标准格式，需要根据上下文判断
3. 返回JSON格式的结果

返回格式示例：
{
  "flags": [
    {
      "value": "flag{xxx}",
      "confidence": 0.95,
      "reasoning": "标准flag格式，位于程序输出末尾"
    }
  ]
}

如果没有找到Flag，返回: {"flags": []}

---
"""
        if context:
            prompt += f"上下文/题目描述:\n{context}\n\n"

        # 限制文本长度
        display_text = text[:2000] if len(text) > 2000 else text
        prompt += f"待分析内容:\n{display_text}\n"

        if decoded_content:
            prompt += "\n解码后的内容:\n"
            for content, enc_type, original in decoded_content[:3]:
                prompt += f"- [{enc_type}] {content[:200]}\n"

        return prompt

    def _parse_ai_response(self, response: Any) -> List[FlagCandidate]:
        """解析AI响应"""
        candidates = []

        try:
            # 处理不同类型的响应
            if hasattr(response, 'content'):
                text = response.content
            elif isinstance(response, dict):
                text = response.get('text', str(response))
            else:
                text = str(response)

            # 提取JSON
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                data = json.loads(json_match.group())
                for item in data.get('flags', []):
                    candidates.append(FlagCandidate(
                        value=item.get('value', ''),
                        confidence=float(item.get('confidence', 0.5)),
                        source='ai:analysis',
                        reasoning=item.get('reasoning', '')
                    ))
        except:
            pass

        return candidates

    def execute_extraction_script(
        self,
        script: str,
        text: str
    ) -> List[str]:
        """
        执行AI生成的提取脚本

        Args:
            script: Python提取脚本
            text: 要处理的文本

        Returns:
            提取到的Flag列表
        """
        if not self.execute_script:
            return []

        if self._script_executor is None:
            self._script_executor = ScriptExecutor()

        return self._script_executor.execute(script, text)

    def extract_first(self, text: str, context: str = "") -> Optional[str]:
        """提取最可能的Flag"""
        candidates = self.extract(text, context, max_candidates=1)
        return candidates[0].value if candidates else None

    def has_flag(self, text: str) -> bool:
        """快速检查是否可能包含Flag"""
        # 先用快速规则检查
        if self.PRE_FILTER.search(text):
            return True
        # 检查编码内容
        decoded = self._try_decode(text)
        for content, _, _ in decoded:
            if self.PRE_FILTER.search(content):
                return True
        return False


class ScriptExecutor:
    """
    安全的脚本执行器

    允许AI生成并执行简单的提取脚本
    """

    # 允许的安全模块
    SAFE_MODULES = {
        're', 'base64', 'json', 'hashlib', 'binascii',
        'string', 'collections', 'itertools'
    }

    # 允许的安全内置函数
    SAFE_BUILTINS = {
        'len', 'str', 'int', 'list', 'dict', 'tuple', 'set',
        'range', 'enumerate', 'zip', 'map', 'filter', 'sorted',
        'reversed', 'any', 'all', 'min', 'max', 'sum', 'abs',
        'chr', 'ord', 'hex', 'bin', 'oct', 'bool', 'type',
        'isinstance', 'print', 'True', 'False', 'None'
    }

    def __init__(self):
        self._allowed_modules = {m: __import__(m) for m in self.SAFE_MODULES}

    def execute(self, script: str, text: str) -> List[str]:
        """
        执行提取脚本

        脚本应该定义一个 extract(text: str) -> List[str] 函数
        """
        # 创建受限的执行环境
        safe_globals = {
            '__builtins__': {k: __builtins__[k] for k in self.SAFE_BUILTINS if k in __builtins__},
            **self._allowed_modules,
            'text': text,
        }

        # 预置模板
        full_script = f'''
import re
import base64
import json

{script}

# 执行提取
result = extract(text)
'''

        try:
            local_vars = {}
            exec(full_script, safe_globals, local_vars)
            result = local_vars.get('result', [])
            return list(result) if result else []
        except Exception as e:
            return []




# 简化的便捷函数
def extract_flags(
    text: str,
    ai_client: Any = None,
    context: str = ""
) -> List[str]:
    """
    便捷函数：提取Flag列表

    Args:
        text: 要分析的文本
        ai_client: 可选的AI客户端
        context: 额外上下文

    Returns:
        Flag值列表
    """
    extractor = AIFlagExtractor(ai_client=ai_client)
    candidates = extractor.extract(text, context)
    return [c.value for c in candidates]


def extract_first_flag(text: str, ai_client: Any = None) -> Optional[str]:
    """便捷函数：提取第一个Flag"""
    extractor = AIFlagExtractor(ai_client=ai_client)
    return extractor.extract_first(text)


def has_flag(text: str) -> bool:
    """便捷函数：检查是否有Flag"""
    return AIFlagExtractor().has_flag(text)


# 兼容旧接口
def extract_flags_from_text(text: str, decode: bool = True) -> List[str]:
    """兼容旧接口"""
    return extract_flags(text)


# 全局实例（无AI模式，仅使用规则）
flag_extractor = AIFlagExtractor(ai_client=None)