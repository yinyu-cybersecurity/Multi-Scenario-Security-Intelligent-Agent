# misc/prompts.py
"""
Misc模块提示词

提供LLM分析用的提示词模板
"""

from typing import Dict, List


def get_misc_analysis_prompt(file_info: Dict) -> str:
    """获取Misc分析提示词"""
    return f"""
你是一个CTF杂项专家，分析以下文件。

## 文件信息
- 类型: {file_info.get('type', 'unknown')}
- 大小: {file_info.get('size', 0)} bytes
- MIME: {file_info.get('mime', 'unknown')}
- MD5: {file_info.get('md5', 'unknown')}

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


def get_steganography_prompt(steg_results: Dict) -> str:
    """获取隐写术分析提示词"""
    return f"""
分析以下隐写术检测结果。

## 检测结果
{steg_results}

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


def get_forensics_prompt(analysis: Dict) -> str:
    """获取取证分析提示词"""
    return f"""
进行取证分析。

## 分析数据
{analysis}

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