# reverse/prompts.py
"""
逆向模块提示词

提供LLM分析用的提示词模板
支持阶段感知和战略上下文注入
"""

from typing import Dict, List, Optional, Any


def _format_stage_info(stage_info: Optional[Dict[str, Any]]) -> str:
    """格式化阶段信息为提示词片段"""
    if not stage_info:
        return ""

    parts = []

    # 阶段基本信息
    stage_name = stage_info.get("stage_name", "")
    stage_type = stage_info.get("stage_type", "")
    if stage_name:
        parts.append(f"- 当前阶段: {stage_name}")
    if stage_type:
        parts.append(f"- 阶段类型: {stage_type}")

    # 阶段目标
    goals = stage_info.get("goals", [])
    if goals:
        parts.append(f"- 阶段目标: {', '.join(goals[:3])}")

    # 主要策略
    primary_strategy = stage_info.get("primary_strategy", "")
    if primary_strategy:
        parts.append(f"- 主攻策略: {primary_strategy}")

    # 阶段提示
    hints = stage_info.get("hints", [])
    if hints:
        parts.append(f"- 阶段提示: {'; '.join(hints[:2])}")

    # 成功标准
    criteria = stage_info.get("success_criteria", {})
    conditions = criteria.get("conditions", [])
    if conditions:
        parts.append(f"- 成功标准: {'; '.join(conditions[:2])}")

    if parts:
        return "\n".join(parts)
    return ""


def _format_strategic_context(strategic_context: Optional[Dict[str, Any]]) -> str:
    """格式化战略上下文为提示词片段"""
    if not strategic_context:
        return ""

    parts = []

    # 空间认知
    position_type = strategic_context.get("position_type", "")
    position_detail = strategic_context.get("position_detail", "")
    if position_type:
        parts.append(f"- 场景类型: {position_type}")
    if position_detail:
        parts.append(f"- 当前位置: {position_detail}")

    # 目标规划
    primary_goal = strategic_context.get("primary_goal", "")
    if primary_goal:
        parts.append(f"- 主要目标: {primary_goal}")

    attack_chain = strategic_context.get("attack_chain", [])
    current_step = strategic_context.get("current_step", 0)
    total_steps = strategic_context.get("total_steps", 0)
    if attack_chain:
        parts.append(f"- 攻击链: {' -> '.join(attack_chain)}")
    if total_steps > 0:
        parts.append(f"- 进度: {current_step}/{total_steps}")

    # 障碍与备选
    blockers = strategic_context.get("blockers", [])
    if blockers:
        parts.append(f"- 当前障碍: {'; '.join(blockers[:3])}")

    alternate_routes = strategic_context.get("alternate_routes", [])
    if alternate_routes:
        parts.append(f"- 备选路径: {'; '.join(alternate_routes[:3])}")

    if parts:
        return "\n".join(parts)
    return ""


def get_reverse_analysis_prompt(
    binary_info: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取逆向分析提示词

    Args:
        binary_info: 二进制文件信息
        stage_info: 阶段信息（来自StagedPlanner）
        strategic_context: 战略上下文（来自StrategicContext）

    Returns:
        格式化后的提示词
    """
    # 构建阶段感知部分
    stage_section = ""
    if stage_info:
        stage_text = _format_stage_info(stage_info)
        if stage_text:
            stage_section = f"""
## 当前阶段信息
{stage_text}
"""

    # 构建战略上下文部分
    context_section = ""
    if strategic_context:
        context_text = _format_strategic_context(strategic_context)
        if context_text:
            context_section = f"""
## 战略上下文
{context_text}
"""

    return f"""
你是一个逆向工程专家，分析以下二进制文件。

## 二进制信息
- 路径: {binary_info.get('path', 'unknown')}
- 架构: {binary_info.get('arch', 'unknown')}
- 函数数量: {binary_info.get('function_count', 0)}
- 字符串数量: {binary_info.get('string_count', 0)}
{stage_section}{context_section}
## 分析任务
1. 确定程序功能
2. 识别关键函数
3. 查找加密/编码逻辑
4. 定位flag相关代码

## 输出格式 (JSON)
{{
  "program_type": "程序类型",
  "key_functions": ["关键函数列表"],
  "algorithm_detected": "检测到的算法",
  "flag_location_hint": "flag位置提示"
}}
"""


def get_algorithm_identification_prompt(
    code: str,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取算法识别提示词

    Args:
        code: 待分析的代码片段
        stage_info: 阶段信息（来自StagedPlanner）
        strategic_context: 战略上下文（来自StrategicContext）

    Returns:
        格式化后的提示词
    """
    # 构建阶段感知部分
    stage_section = ""
    if stage_info:
        stage_text = _format_stage_info(stage_info)
        if stage_text:
            stage_section = f"""
## 当前阶段信息
{stage_text}
"""

    # 构建战略上下文部分
    context_section = ""
    if strategic_context:
        context_text = _format_strategic_context(strategic_context)
        if context_text:
            context_section = f"""
## 战略上下文
{context_text}
"""

    # 根据阶段类型调整提示重点
    stage_type = stage_info.get("stage_type", "") if stage_info else ""
    focus_hint = ""
    if stage_type == "recon" or "静态分析" in str(stage_info.get("stage_name", "")):
        focus_hint = "\n- 重点关注：识别算法类型和基本结构"
    elif stage_type == "discovery" or "动态调试" in str(stage_info.get("stage_name", "")):
        focus_hint = "\n- 重点关注：动态行为和密钥获取方式"
    elif "算法还原" in str(stage_info.get("stage_name", "")):
        focus_hint = "\n- 重点关注：算法细节和参数提取"
    elif "密钥提取" in str(stage_info.get("stage_name", "")):
        focus_hint = "\n- 重点关注：密钥位置和提取方法"

    return f"""
识别以下代码中的算法或加密逻辑。

## 代码
```
{code[:2000]}
```
{stage_section}{context_section}
## 常见CTF算法
- XOR加密
- Base64编码
- 凯撒密码
- RC4/AES/DES加密
- 自定义混淆
{focus_hint}
## 输出格式 (JSON)
{{
  "algorithm": "算法名称",
  "key_or_seed": "密钥或种子值",
  "decryption_steps": ["解密步骤"],
  "code_snippet": "关键代码段"
}}
"""


def get_flag_extraction_prompt(
    analysis: Dict,
    stage_info: Optional[Dict[str, Any]] = None,
    strategic_context: Optional[Dict[str, Any]] = None
) -> str:
    """
    获取flag提取提示词

    Args:
        analysis: 逆向分析结果
        stage_info: 阶段信息（来自StagedPlanner）
        strategic_context: 战略上下文（来自StrategicContext）

    Returns:
        格式化后的提示词
    """
    # 构建阶段感知部分
    stage_section = ""
    if stage_info:
        stage_text = _format_stage_info(stage_info)
        if stage_text:
            stage_section = f"""
## 当前阶段信息
{stage_text}
"""

    # 构建战略上下文部分
    context_section = ""
    if strategic_context:
        context_text = _format_strategic_context(strategic_context)
        if context_text:
            context_section = f"""
## 战略上下文
{context_text}
"""

    # 根据阶段进度调整优先级
    stage_type = stage_info.get("stage_type", "") if stage_info else ""
    priority_hint = ""
    if stage_type == "flag_capture" or "FLAG" in str(stage_info.get("stage_name", "")):
        priority_hint = "\n- 紧急：这是最后阶段，请务必尝试所有可能的方法提取FLAG"

    # 检查是否有备选路径
    alternate_routes = strategic_context.get("alternate_routes", []) if strategic_context else []
    alternate_hint = ""
    if alternate_routes:
        alternate_hint = f"\n- 如果常规方法失败，尝试: {'; '.join(alternate_routes[:2])}"

    return f"""
根据逆向分析结果提取flag。

## 分析结果
{analysis}
{stage_section}{context_section}
## 提取方法
1. 查找硬编码字符串
2. 分析校验逻辑
3. 逆向加密/编码
4. 提取内存数据
{priority_hint}{alternate_hint}
## 输出格式 (JSON)
{{
  "flag_found": true/false,
  "flag_value": "flag值（如找到）",
  "extraction_method": "提取方法",
  "remaining_work": "还需的工作"
}}
"""