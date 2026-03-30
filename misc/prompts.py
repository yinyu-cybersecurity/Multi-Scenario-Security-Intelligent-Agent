# misc/prompts.py
"""
Misc模块提示词

提供LLM分析用的提示词模板
"""

from typing import Dict, List, Optional


def get_misc_analysis_prompt(file_info: Dict,
                             stage_info: Optional[Dict] = None,
                             strategic_context: Optional[Dict] = None) -> str:
    """获取Misc分析提示词"""

    # 阶段信息注入
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段指引
- 阶段名称: {stage_info.get('stage_name', '')}
- 阶段目标: {stage_info.get('goal', '')}
- 成功标准: {stage_info.get('success_criteria', [])}
- 超时限制: {stage_info.get('timeout', 0)}秒
"""

    # 战略上下文注入
    strategic_section = ""
    if strategic_context:
        attack_chain = strategic_context.get('attack_chain', [])
        current_step = strategic_context.get('current_step', 1)
        total_steps = strategic_context.get('total_steps', len(attack_chain))
        current_stage_name = attack_chain[current_step-1] if current_step <= len(attack_chain) else '未知'
        blockers = strategic_context.get('blockers', [])
        alternate_routes = strategic_context.get('alternate_routes', [])
        strategic_section = f"""
## 战略上下文
- 当前位置: {strategic_context.get('position_type', 'misc')}
- 攻击链进度: 第{current_step}步/共{total_steps}步
- 当前阶段: {current_stage_name}
- 主要目标: {strategic_context.get('primary_goal', '获取FLAG')}
- 已知障碍: {', '.join(blockers) if blockers else '无'}
- 备选路径: {', '.join(alternate_routes) if alternate_routes else '无'}
"""

    return f"""
你是一个CTF杂项专家，分析以下文件。

## 文件信息
- 类型: {file_info.get('type', 'unknown')}
- 大小: {file_info.get('size', 0)} bytes
- MIME: {file_info.get('mime', 'unknown')}
- MD5: {file_info.get('md5', 'unknown')}
{stage_section}{strategic_section}
## 分析任务
1. 确定挑战类型
2. 识别隐写术或编码
3. 建议提取方法
4. 定位flag

## 输出格式 (JSON)
{{
  "challenge_type": "stego/forensics/encoding/osint",
  "techniques": ["可能的技术"],
  "extraction_steps": ["提取步骤"],
  "flag_location": "flag可能的位置"
}}
"""


def get_steganography_prompt(steg_results: Dict,
                             stage_info: Optional[Dict] = None,
                             strategic_context: Optional[Dict] = None) -> str:
    """获取隐写术分析提示词"""

    # 阶段信息注入
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段指引
- 阶段名称: {stage_info.get('stage_name', '')}
- 阶段目标: {stage_info.get('goal', '')}
- 成功标准: {stage_info.get('success_criteria', [])}
- 超时限制: {stage_info.get('timeout', 0)}秒
"""

    # 战略上下文注入
    strategic_section = ""
    if strategic_context:
        attack_chain = strategic_context.get('attack_chain', [])
        current_step = strategic_context.get('current_step', 1)
        total_steps = strategic_context.get('total_steps', len(attack_chain))
        current_stage_name = attack_chain[current_step-1] if current_step <= len(attack_chain) else '未知'
        blockers = strategic_context.get('blockers', [])
        alternate_routes = strategic_context.get('alternate_routes', [])
        strategic_section = f"""
## 战略上下文
- 当前位置: {strategic_context.get('position_type', 'misc')}
- 攻击链进度: 第{current_step}步/共{total_steps}步
- 当前阶段: {current_stage_name}
- 主要目标: {strategic_context.get('primary_goal', '获取FLAG')}
- 已知障碍: {', '.join(blockers) if blockers else '无'}
- 备选路径: {', '.join(alternate_routes) if alternate_routes else '无'}
"""

    return f"""
分析以下隐写术检测结果。

## 检测结果
{steg_results}
{stage_section}{strategic_section}
## 常见隐写术
- LSB隐写（图片最低位）
- 文件尾部附加数据
- EXIF元数据隐藏
- 调色板隐写
- 音频频谱图隐写

## 输出格式 (JSON)
{{
  "steg_type": "隐写类型",
  "extraction_method": "提取方法",
  "tool_required": "需要的工具",
  "expected_data": "期望得到的数据类型"
}}
"""


def get_forensics_prompt(analysis: Dict,
                         stage_info: Optional[Dict] = None,
                         strategic_context: Optional[Dict] = None) -> str:
    """获取取证分析提示词"""

    # 阶段信息注入
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段指引
- 阶段名称: {stage_info.get('stage_name', '')}
- 阶段目标: {stage_info.get('goal', '')}
- 成功标准: {stage_info.get('success_criteria', [])}
- 超时限制: {stage_info.get('timeout', 0)}秒
"""

    # 战略上下文注入
    strategic_section = ""
    if strategic_context:
        attack_chain = strategic_context.get('attack_chain', [])
        current_step = strategic_context.get('current_step', 1)
        total_steps = strategic_context.get('total_steps', len(attack_chain))
        current_stage_name = attack_chain[current_step-1] if current_step <= len(attack_chain) else '未知'
        blockers = strategic_context.get('blockers', [])
        alternate_routes = strategic_context.get('alternate_routes', [])
        strategic_section = f"""
## 战略上下文
- 当前位置: {strategic_context.get('position_type', 'misc')}
- 攻击链进度: 第{current_step}步/共{total_steps}步
- 当前阶段: {current_stage_name}
- 主要目标: {strategic_context.get('primary_goal', '获取FLAG')}
- 已知障碍: {', '.join(blockers) if blockers else '无'}
- 备选路径: {', '.join(alternate_routes) if alternate_routes else '无'}
"""

    return f"""
进行取证分析。

## 分析数据
{analysis}
{stage_section}{strategic_section}
## 取证要点
1. 文件签名检查
2. 时间戳分析
3. 元数据提取
4. 已删除数据恢复
5. 嵌入文件提取

## 输出格式 (JSON)
{{
  "evidence": ["发现的证据"],
  "hidden_data": ["隐藏的数据"],
  "timeline": "时间线信息",
  "flag_source": "flag来源"
}}
"""