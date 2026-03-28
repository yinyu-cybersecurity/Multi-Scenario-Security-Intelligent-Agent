# crypto/nodes.py
"""
Crypto分析节点

节点:
- crypto_analyst_node: 加密类型识别与分析
- crypto_solver_node: 尝试解密和破解
"""

import json
from typing import Dict, List, Any
from llm_client import llm_client
from config import config
from logger import get_logger
from .tools import (
    CryptoIdentifier,
    EncodingDecoder,
    ClassicalCipherSolver,
    ModernCryptoSolver,
    HashAnalyzer
)

# 模块日志器
logger = get_logger("Crypto")


def crypto_analyst_node(state: Dict) -> Dict:
    """
    [Crypto分析节点] 识别和分析加密类型

    输入:
        - crypto_findings: 发现的加密文本
        - page_features: 页面特征（可能包含加密线索）

    输出:
        - crypto_analysis: 分析结果
        - identified_encodings: 识别出的编码类型

    工作流程:
        1. 从已知事实和页面特征中提取可能的密文
        2. 自动识别编码/加密类型
        3. 提供解密建议
    """
    logger.info("Starting crypto analysis...")

    # 知识库检索：获取相关加密攻击技术参考
    knowledge_context = ""
    try:
        from rag_builder.retriever import retrieve_relevant_knowledge

        retrieval_result = retrieve_relevant_knowledge(
            query="crypto attack cipher CTF",
            sources=["writeups", "security_resources"],
            top_k=3
        )

        if retrieval_result:
            knowledge_context = "\n".join([r.get("content", "")[:500] for r in retrieval_result])
            logger.info(f"[CryptoAnalyst] Retrieved {len(retrieval_result)} knowledge references")
    except Exception:
        pass  # 静默失败，不影响主流程

    # 收集待分析的密文
    ciphertexts = []

    # 从已知事实中提取
    known_facts = state.get("known_facts", "")
    if known_facts:
        # 尝试提取可能的密文
        import re
        # 匹配Base64
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        ciphertexts.extend(re.findall(b64_pattern, known_facts))
        # 匹配Hex
        hex_pattern = r'[a-fA-F0-9]{16,}'
        ciphertexts.extend(re.findall(hex_pattern, known_facts))

    # 从页面特征中提取
    page_features = state.get("page_features", {})
    for key, value in page_features.items():
        if isinstance(value, str) and len(value) > 10:
            # 检查是否像密文
            if _looks_like_ciphertext(value):
                ciphertexts.append(value)

    # 从攻击结果中提取
    attack_results = state.get("attack_results", [])
    for result in attack_results[-5:]:  # 只看最近5个
        if isinstance(result, dict):
            response = result.get("response", "")
            if response:
                # 提取响应中的密文
                import re
                b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
                ciphertexts.extend(re.findall(b64_pattern, response))

    # 去重
    ciphertexts = list(set(ciphertexts))

    if not ciphertexts:
        logger.warning("No ciphertext found")
        return {
            "crypto_analysis": {"status": "no_ciphertext"},
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    # 分析每个密文
    analysis_results = []
    for ct in ciphertexts[:5]:  # 最多分析5个
        identified = CryptoIdentifier.identify(ct)
        if identified:
            analysis_results.append({
                "ciphertext": ct[:100] + "..." if len(ct) > 100 else ct,
                "possible_types": identified[:3]  # 取前3个可能类型
            })

    # 使用LLM进行深度分析（注入知识库上下文）
    if analysis_results:
        llm_analysis = _llm_crypto_analysis(analysis_results, state, knowledge_context)
    else:
        llm_analysis = "No encryption patterns identified"

    logger.info(f"Analyzed {len(analysis_results)} ciphertexts")

    return {
        "crypto_analysis": {
            "status": "analyzed",
            "results": analysis_results,
            "llm_insight": llm_analysis
        },
        "identified_ciphertexts": ciphertexts[:10],
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def crypto_solver_node(state: Dict) -> Dict:
    """
    [Crypto求解节点] AI驱动的解密和破解

    输入:
        - crypto_analysis: 分析结果
        - identified_ciphertexts: 识别出的密文

    输出:
        - decrypted_data: 解密结果
        - potential_flags: 潜在的flag

    工作流程:
        1. AI决策解密策略
        2. 执行AI生成的解密命令
        3. 验证解密结果
    """
    logger.info("AI driving decryption...")

    crypto_analysis = state.get("crypto_analysis", {})
    if crypto_analysis.get("status") != "analyzed":
        return {
            "error": "No crypto analysis available",
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    results = crypto_analysis.get("results", [])
    if not results:
        return {
            "error": "No ciphertext to decrypt",
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    decrypted_results = []
    potential_flags = []

    for item in results:
        ciphertext = item.get("ciphertext", "").replace("...", "")
        types = item.get("possible_types", [])

        # AI决策解密策略
        decrypt_strategy = _ai_decide_decrypt_strategy(ciphertext, types, state)

        logger.info(f"AI策略: {decrypt_strategy.get('encryption_type')}")

        ai_success = False

        # 执行AI生成的解密命令
        if decrypt_strategy.get("commands"):
            for cmd in decrypt_strategy.get("commands", []):
                try:
                    # 执行Python代码
                    if cmd.startswith("import") or cmd.startswith("from") or cmd.startswith("result"):
                        exec_result = _execute_python_code(cmd)
                        if exec_result.get("success"):
                            plaintext = exec_result.get("result", "")
                            if plaintext and len(plaintext) > 0:
                                decrypted_results.append({
                                    "ciphertext": ciphertext[:50],
                                    "type": decrypt_strategy.get("encryption_type"),
                                    "plaintext": plaintext,
                                    "method": "ai_generated"
                                })
                                ai_success = True
                                if _contains_flag(plaintext):
                                    potential_flags.append(plaintext)
                                break
                except Exception as e:
                    logger.error(f"执行失败: {e}")

        # 如果AI解密失败，尝试规则方法
        if not ai_success:
            for type_info in types:
                confidence = type_info.get("confidence", 0)
                if confidence < 50:
                    continue

                result = _attempt_decrypt(ciphertext, type_info.get("type", ""))
                if result.get("success"):
                    plaintext = result.get("plaintext", "")
                    decrypted_results.append({
                        "ciphertext": ciphertext[:50],
                        "type": type_info.get("type"),
                        "plaintext": plaintext,
                        "confidence": confidence
                    })
                    if _contains_flag(plaintext):
                        potential_flags.append(plaintext)
                    break

    # 尝试古典密码暴力破解
    identified_ciphertexts = state.get("identified_ciphertexts", [])
    for ct in identified_ciphertexts[:3]:
        caesar_results = ClassicalCipherSolver.caesar_bruteforce(ct)
        for r in caesar_results[:3]:
            if r.get("likely"):
                decrypted_results.append({
                    "ciphertext": ct[:50],
                    "type": "caesar",
                    "shift": r["shift"],
                    "plaintext": r["plaintext"],
                    "method": "bruteforce"
                })
                if _contains_flag(r["plaintext"]):
                    potential_flags.append(r["plaintext"])

    logger.info(f"Decrypted {len(decrypted_results)} items, found {len(potential_flags)} potential flags")

    return {
        "decrypted_data": decrypted_results,
        "potential_flags": potential_flags,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _ai_decide_decrypt_strategy(ciphertext: str, possible_types: List[Dict], state: Dict) -> Dict:
    """
    AI决策解密策略

    分析密文特征，动态选择解密方法
    """
    prompt = f"""
分析密文，决策最佳解密策略。

## 密文
{ciphertext[:200]}

## 可能的类型
{json.dumps(possible_types, ensure_ascii=False)}

## 已知事实
{state.get("known_facts", "无")}

## 要求
1. 判断最可能的加密/编码类型
2. 生成具体的解密Python代码
3. 考虑多种可能

## 输出格式 (JSON)
{{
    "encryption_type": "最可能的类型",
    "confidence": 0.85,
    "commands": ["python解密代码"],
    "reasoning": "判断依据"
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

        result = json.loads(response.strip())
        return result

    except Exception as e:
        logger.error(f"AI解密决策失败: {e}")
        return {"encryption_type": "unknown", "commands": []}


def _execute_python_code(code: str) -> Dict:
    """执行Python代码并返回结果"""
    try:
        local_vars = {}
        exec(code, {"__builtins__": __builtins__}, local_vars)
        # 查找result变量
        if "result" in local_vars:
            return {"success": True, "result": str(local_vars["result"])}
        return {"success": True, "result": "执行成功，但未找到result变量"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _looks_like_ciphertext(text: str) -> bool:
    """检查文本是否像密文"""
    if len(text) < 10:
        return False

    # 检查是否是Base64格式
    import re
    if re.match(r'^[A-Za-z0-9+/]+=*$', text):
        return True

    # 检查是否是Hex格式
    if re.match(r'^[a-fA-F0-9]+$', text) and len(text) % 2 == 0:
        return True

    # 检查熵值（高熵可能是加密）
    if len(set(text)) / len(text) > 0.7:
        return True

    return False


def _llm_crypto_analysis(analysis_results: List[Dict], state: Dict, knowledge_context: str = "") -> str:
    """使用LLM进行深度加密分析"""

    # 构建知识库参考部分
    knowledge_section = ""
    if knowledge_context:
        knowledge_section = f"""
## Related Knowledge References
{knowledge_context[:1000]}
"""

    prompt = f"""
Analyze the following ciphertext patterns and provide decryption suggestions.
{knowledge_section}
## Identified Ciphertexts
{json.dumps(analysis_results, indent=2)}

## Known Facts
{state.get("known_facts", "None")}

## Task
1. Identify the most likely encryption/encoding type
2. Suggest decryption approach
3. Look for patterns that might reveal the flag

## Output Format (JSON)
{{
  "most_likely_type": "encoding type",
  "decryption_approach": "step by step approach",
  "hints": ["any hints from context"],
  "potential_flag_patterns": ["patterns to look for"]
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

        result = json.loads(response.strip())
        return json.dumps(result, indent=2)

    except Exception as e:
        return f"LLM analysis failed: {str(e)}"


def _attempt_decrypt(ciphertext: str, enc_type: str) -> Dict:
    """尝试解密"""

    # Hash类型不能直接解密
    if enc_type.startswith("hash_"):
        hash_type = enc_type.replace("hash_", "")
        # 尝试破解
        result = HashAnalyzer.crack_hash(ciphertext, hash_type)
        return result

    # 编码类型
    if enc_type in ["base64", "base32", "hex", "url", "binary", "morse", "rot13"]:
        result = EncodingDecoder.decode(ciphertext, enc_type)
        if result.get("success"):
            return {
                "success": True,
                "plaintext": result["result"],
                "method": enc_type
            }

    # 古典密码
    if enc_type == "caesar":
        results = ClassicalCipherSolver.caesar_bruteforce(ciphertext)
        if results and results[0].get("likely"):
            return {
                "success": True,
                "plaintext": results[0]["plaintext"],
                "shift": results[0]["shift"],
                "method": "caesar"
            }

    return {"success": False, "error": f"Could not decrypt with {enc_type}"}


def _contains_flag(text: str) -> bool:
    """检查文本是否包含flag"""
    import re
    flag_patterns = [
        r'flag\{.*?\}',
        r'FLAG\{.*?\}',
        r'ctf\{.*?\}',
        r'CTF\{.*?\}',
        r'key\{.*?\}',
        r'KEY\{.*?\}'
    ]

    for pattern in flag_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False