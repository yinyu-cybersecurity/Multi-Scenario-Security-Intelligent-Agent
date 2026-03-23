# crypto/prompts.py
"""
Crypto模块提示词

提供LLM分析用的提示词模板
"""

from typing import Dict, List, Optional


def get_crypto_analysis_prompt(features: Dict, known_facts: str) -> str:
    """
    获取加密分析提示词

    Args:
        features: 页面特征
        known_facts: 已知事实

    Returns:
        分析提示词
    """
    return f"""
你是一个密码学专家，专门分析CTF中的加密挑战。

## 页面特征
{features}

## 已知事实
{known_facts}

## 任务
1. 从页面特征中识别可能的加密文本
2. 判断加密类型（编码、古典密码、现代密码）
3. 提供解密建议

## 输出格式 (JSON)
{{
  "identified_ciphertexts": [
    {{
      "text": "密文",
      "location": "来源位置",
      "likely_type": "可能的加密类型"
    }}
  ],
  "analysis": "分析结论",
  "suggested_approach": "推荐的解密方法"
}}
"""


def get_rsa_analysis_prompt(n: str = None, e: str = None, c: str = None,
                            other_params: Dict = None) -> str:
    """
    获取RSA分析提示词

    Args:
        n: 模数
        e: 公钥指数
        c: 密文
        other_params: 其他参数

    Returns:
        RSA分析提示词
    """
    params_str = ""
    if n:
        params_str += f"n = {n}\n"
    if e:
        params_str += f"e = {e}\n"
    if c:
        params_str += f"c = {c}\n"
    if other_params:
        for k, v in other_params.items():
            params_str += f"{k} = {v}\n"

    return f"""
你是一个密码学专家，分析RSA加密挑战。

## 已知参数
{params_str}

## 分析任务
1. 检查是否存在常见RSA漏洞：
   - 小指数攻击 (e=3)
   - Wiener攻击 (d很小)
   - 共模攻击
   - Fermat分解 (p和q接近)
   - Pollard p-1分解

2. 计算相关数值：
   - n的位数
   - 检查n是否在factordb中
   - phi(n)计算

## 输出格式 (JSON)
{{
  "vulnerability_type": "漏洞类型",
  "attack_method": "攻击方法",
  "steps": ["解题步骤"],
  "python_code": "解题Python代码",
  "confidence": 0.95
}}
"""


def get_classical_cipher_prompt(ciphertext: str, cipher_type: str = None) -> str:
    """
    获取古典密码分析提示词

    Args:
        ciphertext: 密文
        cipher_type: 密码类型（可选）

    Returns:
        古典密码分析提示词
    """
    type_hint = f"提示：可能是{cipher_type}" if cipher_type else ""

    return f"""
你是一个古典密码专家，分析以下密文。

## 密文
{ciphertext}

{type_hint}

## 分析任务
1. 识别密码类型（凯撒、栅栏、培根、Vigenere、Playfair等）
2. 如果是多表密码，尝试猜测密钥
3. 验证解密结果是否有意义

## 常见特征
- 凯撒密码：字母偏移，可能有可读单词
- 栅栏密码：字母重新排列
- Vigenere：需要密钥，密钥长度影响周期性
- 培根密码：A/B或两种形式编码

## 输出格式 (JSON)
{{
  "cipher_type": "密码类型",
  "key": "密钥（如适用）",
  "plaintext": "明文",
  "confidence": 0.8,
  "explanation": "解密过程说明"
}}
"""


def get_encoding_detection_prompt(text: str) -> str:
    """
    获取编码检测提示词

    Args:
        text: 待检测文本

    Returns:
        编码检测提示词
    """
    return f"""
识别以下文本的编码类型并提供解码方法。

## 文本
{text}

## 可能的编码类型
1. Base64 - 字母数字+/=
2. Base32 - 大写字母和数字2-7
3. Hex - 0-9a-f
4. URL编码 - %XX格式
5. HTML实体 - &#XX; 或 &name;
6. Unicode - \\uXXXX格式
7. Binary - 0和1
8. Morse - .和-
9. Brainfuck - <>+-[].,

## 输出格式 (JSON)
{{
  "detected_encodings": [
    {{
      "type": "编码类型",
      "confidence": 0.95,
      "decoded": "解码结果"
    }}
  ],
  "best_guess": "最可能的编码类型",
  "final_plaintext": "最终明文"
}}
"""


def get_hash_crack_prompt(hash_value: str, hash_type: str = None,
                          context: str = None) -> str:
    """
    获取Hash破解提示词

    Args:
        hash_value: 哈希值
        hash_type: 哈希类型（可选）
        context: 上下文信息（可选）

    Returns:
        Hash破解提示词
    """
    type_info = f"类型: {hash_type}" if hash_type else "类型: 未知"
    ctx_info = f"\n上下文: {context}" if context else ""

    return f"""
分析并尝试破解以下哈希值。

## 哈希信息
值: {hash_value}
{type_info}
{ctx_info}

## 分析任务
1. 确认哈希类型
2. 检查是否是常见密码的哈希
3. 建议破解方法

## 常见密码
- password, 123456, admin, root
- flag, ctf, secret, key
- 来自上下文的可能的密码

## 输出格式 (JSON)
{{
  "hash_type": "确认的哈希类型",
  "length": 32,
  "potential_passwords": ["可能的密码列表"],
  "cracked": false,
  "plaintext": "破解结果（如果成功）",
  "recommendation": "进一步建议"
}}
"""


def get_crypto_mode_router_prompt(state: Dict) -> str:
    """
    获取Crypto模式路由提示词

    用于判断是否需要切换到Crypto模式

    Args:
        state: 当前状态

    Returns:
        路由决策提示词
    """
    features = state.get("page_features", {})
    known_facts = state.get("known_facts", "")
    attack_results = state.get("attack_results", [])[-3:]

    return f"""
判断是否需要启用Crypto模式进行加密分析。

## 页面特征
{features}

## 已知事实
{known_facts}

## 最近攻击结果
{attack_results}

## 判断标准
1. 页面是否包含明显的加密元素（Base64、Hex、密文提示）
2. 攻击是否发现加密数据
3. 是否存在密码学相关的提示（RSA、AES、DES等关键词）

## 输出格式 (JSON)
{{
  "need_crypto_mode": true/false,
  "reason": "判断理由",
  "priority": "high/medium/low",
  "expected_ciphertexts": ["预期要分析的密文"]
}}
"""