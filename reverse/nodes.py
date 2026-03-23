# reverse/nodes.py
"""
逆向分析节点

节点:
- reverse_analyst_node: 二进制逆向分析
- reverse_decompiler_node: 反编译与算法识别
"""

import json
from typing import Dict, List, Any
from state import CTFState
from llm_client import llm_client
from config import config
from .tools import (
    Disassembler,
    Decompiler,
    StringExtractor,
    FunctionAnalyzer,
    PatternMatcher
)


def reverse_analyst_node(state: Dict) -> Dict:
    """
    [逆向分析节点] 分析二进制文件结构

    输入:
        - binary_path: 二进制文件路径
        - reverse_mode: 是否处于逆向模式

    输出:
        - reverse_info: 逆向分析信息
        - extracted_strings: 提取的字符串
        - functions: 函数列表

    工作流程:
        1. 提取字符串
        2. 分析函数
        3. 检测算法模式
    """
    print("[ReverseAnalyst] Starting reverse analysis...")

    binary_path = state.get("binary_path", "")

    if not binary_path:
        # 尝试从已知事实提取
        known_facts = state.get("known_facts", "")
        import re
        path_match = re.search(r'(?:binary|file|executable)[:\s]+([^\s,]+)', known_facts, re.I)
        if path_match:
            binary_path = path_match.group(1)

    if not binary_path:
        print("[ReverseAnalyst] No binary path found")
        return {
            "reverse_info": {"status": "no_binary"},
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    try:
        # 提取字符串
        strings = StringExtractor.extract(binary_path)

        # 查找flag模式
        flag_strings = StringExtractor.find_flag_patterns(strings)

        # 查找编码字符串
        encoded_strings = StringExtractor.find_encoded_strings(strings)

        # 获取函数列表
        functions = Disassembler._extract_functions(binary_path) if hasattr(Disassembler, '_extract_functions') else []

        # 分析main函数
        main_addr = FunctionAnalyzer.find_main_function(binary_path)

        print(f"[ReverseAnalyst] Found {len(strings)} strings, {len(functions)} functions")

        return {
            "reverse_info": {
                "status": "analyzed",
                "binary_path": binary_path,
                "main_address": hex(main_addr) if main_addr else None,
                "string_count": len(strings),
                "function_count": len(functions),
                "flag_candidates": flag_strings[:5],
                "encoded_strings": {k: v[:5] for k, v in encoded_strings.items()}
            },
            "extracted_strings": strings[:100],
            "functions": functions[:50],
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    except Exception as e:
        print(f"[ReverseAnalyst] Analysis failed: {e}")
        return {
            "reverse_info": {"status": "error", "error": str(e)},
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }


def reverse_decompiler_node(state: Dict) -> Dict:
    """
    [反编译节点] 反编译并识别算法

    输入:
        - reverse_info: 逆向分析信息
        - target_function: 目标函数名

    输出:
        - decompiled_code: 反编译代码
        - algorithm_type: 识别的算法类型
        - key_findings: 关键发现

    工作流程:
        1. 反编译目标函数
        2. 分析代码模式
        3. 识别算法
        4. LLM深度分析
    """
    print("[ReverseDeompiler] Decompiling and analyzing...")

    reverse_info = state.get("reverse_info", {})
    if reverse_info.get("status") != "analyzed":
        return {
            "error": "No reverse analysis available",
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    binary_path = reverse_info.get("binary_path", "")
    target_func = state.get("target_function", "main")

    try:
        # 反编译
        decompiled = Decompiler.decompile(binary_path, target_func)

        # 获取反汇编
        disasm = Disassembler.disassemble_function(binary_path, target_func)

        # 分析函数
        analysis = FunctionAnalyzer.analyze_function(disasm)

        # 匹配模式
        patterns = PatternMatcher.match_patterns(disasm)

        # 查找常量
        constants = PatternMatcher.find_constant_values(disasm)

        # LLM深度分析
        llm_findings = _llm_reverse_analysis(decompiled, analysis, patterns, state)

        # 识别算法
        algorithm = PatternMatcher.identify_algorithm(analysis)

        print(f"[ReverseDeompiler] Decompiled {len(decompiled)} chars, found {len(patterns)} patterns")

        return {
            "decompiled_code": decompiled[:2000],  # 限制长度
            "algorithm_type": algorithm,
            "function_analysis": analysis,
            "matched_patterns": patterns,
            "constants": constants[:20],
            "key_findings": llm_findings,
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    except Exception as e:
        print(f"[ReverseDeompiler] Decompilation failed: {e}")
        return {
            "error": str(e),
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }


def _llm_reverse_analysis(decompiled: str, analysis: Dict,
                         patterns: List, state: Dict) -> str:
    """使用LLM进行深度逆向分析"""

    prompt = f"""
Analyze this decompiled code for CTF reverse engineering.

## Decompiled Code
```
{decompiled[:1500]}
```

## Analysis Results
- Has loops: {analysis.get('has_loops', False)}
- Has crypto: {analysis.get('has_crypto', False)}
- Crypto type: {analysis.get('crypto_type', 'None')}
- Calls: {analysis.get('calls', [])}

## Matched Patterns
{json.dumps(patterns, indent=2)}

## Task
1. Identify the algorithm or logic
2. Find potential flag checking or encoding
3. Suggest reverse engineering approach
4. Extract any hardcoded values or keys

## Output Format (JSON)
{{
  "algorithm": "identified algorithm",
  "logic_summary": "brief description",
  "potential_keys": ["possible keys or constants"],
  "reverse_approach": "suggested approach",
  "flag_location": "where flag might be"
}}
"""

    try:
        response = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True
        )

        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]

        return response.strip()

    except Exception as e:
        return f"LLM analysis failed: {str(e)}"