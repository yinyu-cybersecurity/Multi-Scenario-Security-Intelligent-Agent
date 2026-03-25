# misc/nodes.py
"""
Misc分析节点

节点:
- misc_analyst_node: 文件分析与隐写检测
- misc_extractor_node: 数据提取与转换
"""

import json
import os
from typing import Dict, List, Any
from state import CTFState
from llm_client import llm_client
from config import config
from logger import get_logger
from .tools import (
    SteganographyDetector,
    ForensicsAnalyzer,
    MediaAnalyzer,
    TrafficAnalyzer,
    EncodingConverter,
    FileType
)

# 模块日志器
logger = get_logger("Misc")


def misc_analyst_node(state: Dict) -> Dict:
    """
    [Misc分析节点] 分析文件类型和隐写术

    输入:
        - misc_files: 待分析的文件列表
        - file_path: 单个文件路径

    输出:
        - file_info: 文件信息
        - steg_results: 隐写检测结果
        - misc_analysis: 分析结论

    工作流程:
        1. 确定文件类型
        2. 检测隐写术
        3. 分析元数据
    """
    print("[MiscAnalyst] Starting file analysis...")

    # 获取文件路径
    file_path = state.get("file_path", "") or state.get("misc_file", "")

    if not file_path:
        # 尝试从附件获取
        attachments = state.get("attachments", [])
        for att in attachments:
            if att.get("path"):
                file_path = att.get("path")
                break

    if not file_path or not os.path.exists(file_path):
        print("[MiscAnalyst] No valid file path found")
        return {
            "misc_analysis": {"status": "no_file"},
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    try:
        # 基本文件分析
        file_info = ForensicsAnalyzer.analyze_file(file_path)

        # 隐写术检测
        steg_results = {}

        # 检查文件尾部附加数据
        trailer_data = SteganographyDetector.check_file_trailer(file_path)
        if trailer_data:
            steg_results['trailer_data'] = trailer_data[:100].hex()
            # 检查是否有可读内容
            try:
                decoded = trailer_data.decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in decoded):
                    steg_results['trailer_decoded'] = decoded[:200]
            except Exception:
                pass

        # 检查LSB隐写（图片）
        if file_info.file_type == FileType.IMAGE:
            lsb_data = SteganographyDetector.extract_lsb(file_path)
            if lsb_data:
                steg_results['lsb_data'] = str(lsb_data)[:200]

            # 检查EXIF
            exif = SteganographyDetector.check_exif_data(file_path)
            if exif:
                steg_results['exif'] = exif

        # 媒体分析
        media_analysis = {}
        if file_info.file_type == FileType.IMAGE:
            media_analysis = MediaAnalyzer.analyze_image(file_path)
        elif file_info.file_type == FileType.AUDIO:
            media_analysis = MediaAnalyzer.analyze_audio(file_path)

        # 查找嵌入文件
        embedded = ForensicsAnalyzer.find_embedded_files(file_path)

        # LLM分析
        llm_insight = _llm_misc_analysis(file_info, steg_results, embedded, state)

        print(f"[MiscAnalyst] Analysis complete: {file_info.file_type.value}")

        return {
            "file_info": {
                "path": file_info.path,
                "type": file_info.file_type.value,
                "mime": file_info.mime_type,
                "size": file_info.size,
                "md5": file_info.hash_md5
            },
            "steg_results": steg_results,
            "media_analysis": media_analysis,
            "embedded_files": embedded,
            "misc_analysis": {
                "status": "analyzed",
                "findings": list(steg_results.keys()),
                "llm_insight": llm_insight
            },
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    except Exception as e:
        print(f"[MiscAnalyst] Analysis failed: {e}")
        return {
            "misc_analysis": {"status": "error", "error": str(e)},
            "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5,
            "execution_steps": state.get("execution_steps", 0) + 1
        }


def misc_extractor_node(state: Dict) -> Dict:
    """
    [Misc提取节点] 提取隐藏数据

    输入:
        - file_info: 文件信息
        - steg_results: 隐写检测结果

    输出:
        - extracted_data: 提取的数据
        - potential_flags: 潜在的flag

    工作流程:
        1. 根据分析结果选择提取方法
        2. 尝试各种解码
        3. 验证提取结果
    """
    print("[MiscExtractor] Extracting hidden data...")

    misc_analysis = state.get("misc_analysis", {})
    if misc_analysis.get("status") != "analyzed":
        return {
            "error": "No misc analysis available",
            "execution_steps": state.get("execution_steps", 0) + 1
        }

    file_info = state.get("file_info", {})
    steg_results = state.get("steg_results", {})

    extracted = []
    potential_flags = []

    # 提取尾部数据
    if 'trailer_data' in steg_results:
        trailer_hex = steg_results['trailer_data']
        try:
            trailer_bytes = bytes.fromhex(trailer_hex)
            extracted.append({
                "method": "file_trailer",
                "data": trailer_bytes.decode('utf-8', errors='ignore')[:200]
            })
        except Exception:
            pass

    # 提取LSB数据
    if 'lsb_data' in steg_results:
        extracted.append({
            "method": "lsb_extraction",
            "data": steg_results['lsb_data']
        })

    # 流量分析（如果是pcap）
    file_type = file_info.get("type", "")
    file_path = file_info.get("path", "")

    if file_type == "pcap" or (file_path and file_path.endswith('.pcap')):
        traffic_result = TrafficAnalyzer.analyze_pcap(file_path)
        extracted.append({
            "method": "traffic_analysis",
            "data": str(traffic_result)[:500]
        })

    # 尝试编码转换
    for key, value in steg_results.items():
        if isinstance(value, str) and len(value) > 10:
            # 自动检测编码
            detected = EncodingConverter.auto_detect(value)
            if detected:
                decoded = EncodingConverter.try_decode(value)
                for enc_type, dec_value in decoded.items():
                    extracted.append({
                        "method": f"encoding_{enc_type}",
                        "original": value[:50],
                        "decoded": dec_value[:200]
                    })

    # 查找flag模式
    for item in extracted:
        data = str(item.get("data", ""))
        flag_matches = _find_flags(data)
        potential_flags.extend(flag_matches)

    # 也从已知事实中查找
    known_facts = state.get("known_facts", "")
    flag_matches = _find_flags(known_facts)
    potential_flags.extend(flag_matches)

    # 去重
    potential_flags = list(set(potential_flags))

    print(f"[MiscExtractor] Extracted {len(extracted)} items, {len(potential_flags)} potential flags")

    return {
        "extracted_data": extracted,
        "potential_flags": potential_flags,
        "execution_steps": state.get("execution_steps", 0) + 1
    }


def _find_flags(text: str) -> List[str]:
    """查找flag模式"""
    flags = []
    patterns = [
        r'flag\{[^\}]+\}',
        r'FLAG\{[^\}]+\}',
        r'ctf\{[^\}]+\}',
        r'CTF\{[^\}]+\}',
        r'key\{[^\}]+\}'
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        flags.extend(matches)

    return flags


def _llm_misc_analysis(file_info: Any, steg_results: Dict,
                       embedded: List, state: Dict) -> str:
    """使用LLM进行Misc分析"""

    prompt = f"""
Analyze this file for CTF miscellaneous challenges.

## File Information
- Type: {file_info.file_type.value if hasattr(file_info, 'file_type') else 'unknown'}
- Size: {file_info.size if hasattr(file_info, 'size') else 'unknown'}
- MIME: {file_info.mime_type if hasattr(file_info, 'mime_type') else 'unknown'}

## Steganography Results
{json.dumps(steg_results, indent=2, default=str)[:1000]}

## Embedded Files Found
{json.dumps(embedded, indent=2, default=str)[:500]}

## Task
1. Determine the challenge type (stego, forensics, encoding, etc.)
2. Identify extraction methods to try
3. Look for flag patterns
4. Suggest next steps

## Output Format (JSON)
{{
  "challenge_type": "stego/forensics/encoding/osint",
  "extraction_methods": ["method1", "method2"],
  "flag_hints": ["possible flag locations"],
  "next_steps": ["recommended actions"]
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


import re  # Add this import at the top