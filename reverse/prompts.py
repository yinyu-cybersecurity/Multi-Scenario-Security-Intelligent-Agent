# reverse/prompts.py
"""
逆向模块提示词

提供LLM分析用的提示词模板
"""

from typing import Dict, List


def get_reverse_analysis_prompt(binary_info: Dict) -> str:
    """获取逆向分析提示词"""
    return f"""
你是一个逆向工程专家，分析以下二进制文件。

## 二进制信息
- 路径: {binary_info.get('path', 'unknown')}
- 架构: {binary_info.get('arch', 'unknown')}
- 函数数量: {binary_info.get('function_count', 0)}
- 字符串数量: {binary_info.get('string_count', 0)}

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


def get_algorithm_identification_prompt(code: str) -> str:
    """获取算法识别提示词"""
    return f"""
识别以下代码中的算法或加密逻辑。

## 代码
```
{code[:2000]}
```

## 常见CTF算法
- XOR加密
- Base64编码
- 凯撒密码
- RC4/AES/DES加密
- 自定义混淆

## 输出格式 (JSON)
{{
  "algorithm": "算法名称",
  "key_or_seed": "密钥或种子值",
  "decryption_steps": ["解密步骤"],
  "code_snippet": "关键代码段"
}}
"""


def get_flag_extraction_prompt(analysis: Dict) -> str:
    """获取flag提取提示词"""
    return f"""
根据逆向分析结果提取flag。

## 分析结果
{analysis}

## 提取方法
1. 查找硬编码字符串
2. 分析校验逻辑
3. 逆向加密/编码
4. 提取内存数据

## 输出格式 (JSON)
{{
  "flag_found": true/false,
  "flag_value": "flag值（如找到）",
  "extraction_method": "提取方法",
  "remaining_work": "还需的工作"
}}
"""