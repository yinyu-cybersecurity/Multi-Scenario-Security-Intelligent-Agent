# hybrid_detector.py
r"""
混合检测器 - 正则+AI确认框架

设计理念:
=========
本模块实现"快速正则筛选 + AI智能确认"的两级检测架构，
平衡检测速度与准确性：

1. 三级置信度处理策略
   ┌─────────────────────────────────────────────────────────────┐
   │  HIGH (高置信度): 正则完全匹配                              │
   │  - 行为: 直接返回结果（可配置AI快速复核）                    │
   │  - 场景: FLAG格式、精确错误信息、固定凭据格式               │
   │  - 优势: 毫秒级响应，零API成本                              │
   ├─────────────────────────────────────────────────────────────┤
   │  MEDIUM (中置信度): 正则部分匹配                            │
   │  - 行为: AI快速确认（15秒超时）                             │
   │  - 场景: 模糊的SQL错误、部分路径泄露、疑似凭据              │
   │  - 优势: 平衡速度与准确性                                   │
   ├─────────────────────────────────────────────────────────────┤
   │  LOW (低置信度): 无匹配但场景相关                           │
   │  - 行为: AI深度分析（30秒超时）                             │
   │  - 场景: 异常响应、可疑文本、复杂漏洞特征                   │
   │  - 优势: 发现未知威胁，覆盖正则盲区                         │
   └─────────────────────────────────────────────────────────────┘

2. 预置正则模式（保留高价值检测规则）
   - FLAG检测: flag{...}, FLAG{...}, ctf{...}
   - SQL错误: syntax error, mysql_fetch, oracle error, sqlstate
   - 路径泄露: /var/www, C:\Users, /etc/passwd, web.config
   - 凭据格式: username=xxx password=xxx, jdbc连接串
   - IP格式: 内网IP、公网IP、CIDR格式

3. 性能优化
   - 正则预编译: 启动时编译所有模式
   - 并行匹配: 多模式并行检测
   - 早退机制: 高置信度匹配后立即返回
   - 结果缓存: 相同输入复用结果

4. AI确认策略
   - 快速确认: 简短prompt，最小token消耗
   - 深度分析: 详细上下文，精确判断
   - 失败降级: AI不可用时返回正则结果

使用示例:
    detector = HybridDetector()

    # 高置信度检测
    result = detector.detect("flag{this_is_a_flag}")
    # result.confidence == ConfidenceLevel.HIGH
    # result.type == "flag"

    # 中置信度检测
    result = detector.detect("Error: syntax near 'SELECT'")
    # result.confidence == ConfidenceLevel.MEDIUM
    # result.type == "sql_error"

    # 低置信度检测（需要AI分析）
    result = detector.detect("Warning: Something went wrong", context="sqli_test")
    # result.confidence == ConfidenceLevel.LOW
    # 需要调用 ai_confirm() 进行深度分析
"""

import re
import time
from enum import Enum
from typing import Dict, List, Optional, TypedDict, Any, Tuple
from dataclasses import dataclass, field

from logger import get_logger
from config import config
from llm_client import llm_client, LLMResult, LLMErrorType

logger = get_logger("hybrid_detector")


# =============================================================================
# 类型定义
# =============================================================================

class ConfidenceLevel(Enum):
    """置信度级别"""
    HIGH = "high"      # 正则完全匹配，高置信度
    MEDIUM = "medium"  # 正则部分匹配，中置信度
    LOW = "low"        # 无匹配但场景相关，低置信度


class DetectionType(Enum):
    """检测类型"""
    FLAG = "flag"                    # CTF Flag
    SQL_ERROR = "sql_error"          # SQL错误信息
    PATH_LEAK = "path_leak"          # 路径泄露
    CREDENTIAL = "credential"        # 凭据格式
    IP_ADDRESS = "ip_address"        # IP地址
    ERROR_MESSAGE = "error_message"  # 通用错误信息
    XSS = "xss"                      # XSS特征
    LFI = "lfi"                      # 本地文件包含
    RCE = "rce"                      # 远程命令执行
    UNKNOWN = "unknown"              # 未知类型


@dataclass
class PatternMatch:
    """正则匹配结果"""
    pattern_name: str
    pattern_type: DetectionType
    match_text: str
    start_pos: int
    end_pos: int
    confidence: ConfidenceLevel
    groups: Tuple[str, ...] = field(default_factory=tuple)


class DetectionResult(TypedDict):
    """检测结果"""
    detected: bool                                    # 是否检测到
    confidence: str                                    # 置信度级别
    detection_type: str                                # 检测类型
    matched_text: Optional[str]                        # 匹配文本
    matches: List[Dict[str, Any]]                      # 所有匹配详情
    ai_confirmed: bool                                 # AI是否确认
    ai_analysis: Optional[str]                          # AI分析结果
    processing_time_ms: float                           # 处理时间(毫秒)


# =============================================================================
# 预置正则模式
# =============================================================================

# 高置信度模式 - 精确匹配
HIGH_CONFIDENCE_PATTERNS = {
    # FLAG检测 - CTF标准格式
    "flag_standard": {
        "pattern": r"(?i)(flag|ctf)\{[^\}]+\}",
        "type": DetectionType.FLAG,
        "description": "CTF Flag标准格式"
    },
    "flag_format_v1": {
        "pattern": r"FLAG\{[A-Za-z0-9_\-]+\}",
        "type": DetectionType.FLAG,
        "description": "FLAG{}格式"
    },
    "flag_format_v2": {
        "pattern": r"flag\{[a-zA-Z0-9_\-\.]+\}",
        "type": DetectionType.FLAG,
        "description": "flag{}格式"
    },

    # SQL错误 - 精确错误信息
    "sql_mysql_error": {
        "pattern": r"(?i)(mysql_fetch_array|mysql_num_rows|mysql_query)",
        "type": DetectionType.SQL_ERROR,
        "description": "MySQL函数错误"
    },
    "sql_syntax_error": {
        "pattern": r"(?i)sql syntax.*?mysql|syntax error.*?query",
        "type": DetectionType.SQL_ERROR,
        "description": "SQL语法错误"
    },
    "sql_oracle_error": {
        "pattern": r"(?i)(ORA-\d{5}|oracle.*?error)",
        "type": DetectionType.SQL_ERROR,
        "description": "Oracle错误"
    },
    "sql_postgres_error": {
        "pattern": r"(?i)(PG::Error|PostgreSQL.*?ERROR)",
        "type": DetectionType.SQL_ERROR,
        "description": "PostgreSQL错误"
    },

    # 路径泄露 - 精确路径
    "path_www": {
        "pattern": r"/var/www/(html|vhosts)/[^\s<>\"']+",
        "type": DetectionType.PATH_LEAK,
        "description": "Linux Web路径"
    },
    "path_etc_passwd": {
        "pattern": r"/etc/(passwd|shadow|hosts)",
        "type": DetectionType.PATH_LEAK,
        "description": "Linux系统文件路径"
    },
    "path_windows": {
        "pattern": r"[A-Z]:\\(Users|Windows|Program Files)[\\\/][^\s<>\"']+",
        "type": DetectionType.PATH_LEAK,
        "description": "Windows系统路径"
    },
    "path_config": {
        "pattern": r"(?i)(web\.config|php\.ini|\.htaccess|config\.php)",
        "type": DetectionType.PATH_LEAK,
        "description": "配置文件路径"
    },

    # 凭据格式 - 明确的凭据模式
    "credential_jdbc": {
        "pattern": r"jdbc:[a-z]+://[^\s<>\"']+(?:user|username|pwd|password)=[^\s&<>\"']+",
        "type": DetectionType.CREDENTIAL,
        "description": "JDBC连接串"
    },
    "credential_basic": {
        "pattern": r"(?i)(username|user|login|account)\s*[=:]\s*[^\s]+\s+(password|pass|pwd)\s*[=:]\s*[^\s]+",
        "type": DetectionType.CREDENTIAL,
        "description": "用户名密码对"
    },
    "credential_auth_header": {
        "pattern": r"(?i)(Authorization|Auth)[\s\-]*(Basic|Bearer)\s+[A-Za-z0-9+/=]+",
        "type": DetectionType.CREDENTIAL,
        "description": "认证头信息"
    },
}

# 中置信度模式 - 模糊匹配
MEDIUM_CONFIDENCE_PATTERNS = {
    # SQL错误 - 模糊错误信息
    "sql_generic_error": {
        "pattern": r"(?i)(sql.*?error|database.*?error|query.*?failed)",
        "type": DetectionType.SQL_ERROR,
        "description": "通用SQL错误"
    },
    "sql_injection_hint": {
        "pattern": r"(?i)(syntax.*?near|unexpected.*?token|quoted string.*?terminated)",
        "type": DetectionType.SQL_ERROR,
        "description": "SQL注入提示"
    },

    # 路径泄露 - 模糊路径
    "path_generic": {
        "pattern": r"(?i)(/[a-z_]+/[a-z_]+/[^\s<>\"']+\.(php|asp|aspx|jsp))",
        "type": DetectionType.PATH_LEAK,
        "description": "通用Web路径"
    },
    "path_absolute": {
        "pattern": r"(?i)(?:^|[^a-z])(/[a-z]{2,}(?:/[a-z0-9_\-\.]+){2,})(?:$|[^a-z0-9_\-\.\/])",
        "type": DetectionType.PATH_LEAK,
        "description": "绝对路径"
    },

    # 凭据格式 - 模糊凭据
    "credential_generic": {
        "pattern": r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*[a-z0-9_\-]{8,}",
        "type": DetectionType.CREDENTIAL,
        "description": "API密钥"
    },
    "credential_email": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\s*[:：]\s*[^\s]+)?",
        "type": DetectionType.CREDENTIAL,
        "description": "邮箱凭据"
    },

    # 错误信息
    "error_stack_trace": {
        "pattern": r"(?i)(stack trace|traceback|exception.*?at\s+[a-z])",
        "type": DetectionType.ERROR_MESSAGE,
        "description": "堆栈跟踪"
    },
    "error_debug_info": {
        "pattern": r"(?i)(debug.*?info|warning.*?file|fatal.*?error)",
        "type": DetectionType.ERROR_MESSAGE,
        "description": "调试信息"
    },

    # XSS特征
    "xss_script": {
        "pattern": r"(?i)<script[^>]*>[\s\S]*?</script>",
        "type": DetectionType.XSS,
        "description": "Script标签"
    },
    "xss_event": {
        "pattern": r"(?i)on(error|load|click|mouse|focus|blur)\s*=",
        "type": DetectionType.XSS,
        "description": "事件处理器"
    },

    # LFI特征
    "lfi_parameter": {
        "pattern": r"(?i)(file|path|page|include)\s*[=:]\s*[^\s]+\.(php|asp|aspx|jsp)",
        "type": DetectionType.LFI,
        "description": "文件包含参数"
    },

    # RCE特征
    "rce_command": {
        "pattern": r"(?i)(exec|system|shell|passthru|popen)\s*[\(]",
        "type": DetectionType.RCE,
        "description": "命令执行函数"
    },
}

# IP地址模式（独立处理）
IP_PATTERNS = {
    "ip_private": {
        "pattern": r"(?:(?:10\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|172\.(?:1[6-9]|2\d|3[01])|(?:192\.168))(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){2})",
        "type": DetectionType.IP_ADDRESS,
        "description": "内网IP地址"
    },
    "ip_public": {
        "pattern": r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d\.])",
        "type": DetectionType.IP_ADDRESS,
        "description": "公网IP地址"
    },
    "ip_cidr": {
        "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}",
        "type": DetectionType.IP_ADDRESS,
        "description": "CIDR格式IP"
    },
}


# =============================================================================
# AI确认Prompt模板
# =============================================================================

AI_QUICK_CONFIRM_PROMPT = """你是一个安全检测助手。请快速判断以下文本中是否包含有价值的{type_desc}。

文本内容:
{content}

只需要回答:
- YES: 确认包含有价值信息
- NO: 误报，不包含有价值信息
- PARTIAL: 部分匹配，需要进一步分析

回答(只回答YES/NO/PARTIAL):"""

AI_DEEP_ANALYSIS_PROMPT = """你是一个专业的安全检测助手。请分析以下内容是否包含安全隐患或有价值的信息。

上下文场景: {context}

待分析内容:
{content}

请分析:
1. 检测类型: 指出这是什么类型的安全问题(如SQL注入、路径泄露、凭据泄露等)
2. 置信度: 高/中/低
3. 风险等级: 严重/高/中/低
4. 具体内容: 提取敏感信息的具体内容
5. 建议: 后续应该怎么处理

请用JSON格式回答:
{{
    "detected": true/false,
    "type": "检测类型",
    "confidence": "high/medium/low",
    "risk": "critical/high/medium/low",
    "content": "具体内容",
    "recommendation": "处理建议"
}}"""


# =============================================================================
# HybridDetector 主类
# =============================================================================

class HybridDetector:
    """
    混合检测器 - 正则+AI确认

    核心功能:
    1. 正则快速筛选 - 毫秒级响应
    2. AI智能确认 - 高准确性判断
    3. 分级置信度 - 按场景选择策略

    使用方式:
        detector = HybridDetector()
        result = detector.detect(text)
        if result["confidence"] == "medium":
            # 需要AI确认
            result = detector.ai_confirm(text, result)
    """

    def __init__(
        self,
        quick_confirm_timeout: int = 15,
        deep_analysis_timeout: int = 30,
        high_confidence_ai_verify: bool = False,
        enable_cache: bool = True
    ):
        """
        初始化混合检测器

        Args:
            quick_confirm_timeout: AI快速确认超时(秒)
            deep_analysis_timeout: AI深度分析超时(秒)
            high_confidence_ai_verify: 高置信度是否进行AI复核
            enable_cache: 是否启用结果缓存
        """
        self.quick_confirm_timeout = quick_confirm_timeout
        self.deep_analysis_timeout = deep_analysis_timeout
        self.high_confidence_ai_verify = high_confidence_ai_verify
        self.enable_cache = enable_cache

        # 编译正则模式
        self._compiled_high = self._compile_patterns(HIGH_CONFIDENCE_PATTERNS)
        self._compiled_medium = self._compile_patterns(MEDIUM_CONFIDENCE_PATTERNS)
        self._compiled_ip = self._compile_patterns(IP_PATTERNS)

        # 结果缓存
        self._cache: Dict[str, DetectionResult] = {}
        self._cache_max_size = 1000

        logger.info(f"HybridDetector initialized: quick_timeout={quick_confirm_timeout}s, "
                   f"deep_timeout={deep_analysis_timeout}s, ai_verify={high_confidence_ai_verify}")

    def _compile_patterns(
        self,
        patterns: Dict[str, Dict]
    ) -> Dict[str, Tuple[re.Pattern, DetectionType, str]]:
        """
        编译正则模式

        Args:
            patterns: 模式字典

        Returns:
            编译后的模式字典 {name: (compiled_pattern, type, description)}
        """
        compiled = {}
        for name, info in patterns.items():
            try:
                compiled_pattern = re.compile(info["pattern"])
                compiled[name] = (compiled_pattern, info["type"], info["description"])
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{name}': {e}")
        return compiled

    def detect(
        self,
        content: str,
        context: Optional[str] = None,
        types: Optional[List[DetectionType]] = None
    ) -> DetectionResult:
        """
        检测文本内容

        Args:
            content: 待检测文本
            context: 上下文场景(如sqli_test, lfi_scan等)
            types: 限定检测类型列表，None表示检测所有类型

        Returns:
            DetectionResult: 检测结果
        """
        start_time = time.time()

        # 检查缓存
        cache_key = self._get_cache_key(content, context, types)
        if self.enable_cache and cache_key in self._cache:
            cached_result = self._cache[cache_key]
            logger.debug(f"Using cached result for content (hash: {cache_key[:16]}...)")
            return cached_result

        # 1. 高置信度检测
        high_matches = self._match_patterns(content, self._compiled_high, types)
        if high_matches:
            result = self._build_result(
                detected=True,
                confidence=ConfidenceLevel.HIGH,
                matches=high_matches,
                ai_confirmed=False
            )
            self._save_cache(cache_key, result)
            result["processing_time_ms"] = (time.time() - start_time) * 1000
            return result

        # 2. 中置信度检测
        medium_matches = self._match_patterns(content, self._compiled_medium, types)
        if medium_matches:
            result = self._build_result(
                detected=True,
                confidence=ConfidenceLevel.MEDIUM,
                matches=medium_matches,
                ai_confirmed=False
            )
            self._save_cache(cache_key, result)
            result["processing_time_ms"] = (time.time() - start_time) * 1000
            return result

        # 3. IP地址检测（独立处理）
        ip_matches = self._match_patterns(content, self._compiled_ip, types)
        if ip_matches:
            result = self._build_result(
                detected=True,
                confidence=ConfidenceLevel.MEDIUM,
                matches=ip_matches,
                ai_confirmed=False
            )
            self._save_cache(cache_key, result)
            result["processing_time_ms"] = (time.time() - start_time) * 1000
            return result

        # 4. 低置信度（无正则匹配）
        result = self._build_result(
            detected=False,
            confidence=ConfidenceLevel.LOW,
            matches=[],
            ai_confirmed=False
        )

        # 如果有上下文，记录供后续AI分析
        if context:
            result["context"] = context

        result["processing_time_ms"] = (time.time() - start_time) * 1000
        return result

    def ai_confirm(
        self,
        content: str,
        detection_result: DetectionResult,
        quick_mode: bool = True
    ) -> DetectionResult:
        """
        AI确认检测结果

        Args:
            content: 待确认内容
            detection_result: 正则检测结果
            quick_mode: 是否快速模式(True: 15秒超时, False: 30秒超时)

        Returns:
            更新后的检测结果
        """
        start_time = time.time()
        confidence = detection_result["confidence"]

        # 选择超时和模式
        if quick_mode or confidence == ConfidenceLevel.MEDIUM.value:
            timeout = self.quick_confirm_timeout
            prompt_template = AI_QUICK_CONFIRM_PROMPT
        else:
            timeout = self.deep_analysis_timeout
            prompt_template = AI_DEEP_ANALYSIS_PROMPT

        # 构建prompt
        type_desc = self._get_type_description(detection_result.get("detection_type", "unknown"))
        prompt = prompt_template.format(
            content=content[:2000],  # 限制长度
            type_desc=type_desc,
            context=detection_result.get("context", "未知场景")
        )

        try:
            # 调用AI
            ai_result = llm_client.call_with_details(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                timeout=timeout
            )

            if ai_result.success:
                # 更新结果
                detection_result["ai_confirmed"] = True
                detection_result["ai_analysis"] = ai_result.content

                # 解析AI响应，更新置信度
                self._update_confidence_from_ai(detection_result, ai_result.content, quick_mode)

                logger.debug(f"AI confirmation completed: "
                           f"type={detection_result['detection_type']}, "
                           f"detected={detection_result['detected']}, "
                           f"time={ai_result.duration:.2f}s")
            else:
                logger.warning(f"AI confirmation failed: {ai_result.error_message}")
                detection_result["ai_confirmed"] = False
                detection_result["ai_analysis"] = f"AI调用失败: {ai_result.error_message}"

        except Exception as e:
            logger.error(f"AI confirmation error: {e}")
            detection_result["ai_confirmed"] = False
            detection_result["ai_analysis"] = f"AI调用异常: {str(e)}"

        detection_result["processing_time_ms"] = (time.time() - start_time) * 1000
        return detection_result

    def detect_with_ai(
        self,
        content: str,
        context: Optional[str] = None,
        types: Optional[List[DetectionType]] = None
    ) -> DetectionResult:
        """
        一步到位：检测并AI确认

        自动根据置信度决定是否需要AI确认:
        - HIGH: 直接返回（除非配置了AI复核）
        - MEDIUM: 快速AI确认
        - LOW: 深度AI分析

        Args:
            content: 待检测文本
            context: 上下文场景
            types: 限定检测类型列表

        Returns:
            完整的检测结果（包含AI确认）
        """
        # 第一步：正则检测
        result = self.detect(content, context, types)

        # 第二步：根据置信度决定是否AI确认
        confidence = result["confidence"]

        if confidence == ConfidenceLevel.HIGH.value:
            if self.high_confidence_ai_verify:
                result = self.ai_confirm(content, result, quick_mode=True)

        elif confidence == ConfidenceLevel.MEDIUM.value:
            result = self.ai_confirm(content, result, quick_mode=True)

        elif confidence == ConfidenceLevel.LOW.value:
            if context:  # 只有有上下文才进行AI分析
                result = self.ai_confirm(content, result, quick_mode=False)

        return result

    def _match_patterns(
        self,
        content: str,
        patterns: Dict[str, Tuple[re.Pattern, DetectionType, str]],
        types: Optional[List[DetectionType]] = None
    ) -> List[Dict[str, Any]]:
        """
        执行模式匹配

        Args:
            content: 待匹配内容
            patterns: 编译后的模式字典
            types: 限定检测类型

        Returns:
            匹配结果列表
        """
        matches = []

        for name, (compiled, detection_type, description) in patterns.items():
            # 类型过滤
            if types and detection_type not in types:
                continue

            for match in compiled.finditer(content):
                matches.append({
                    "pattern_name": name,
                    "type": detection_type.value,
                    "description": description,
                    "matched_text": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "groups": match.groups()
                })

        return matches

    def _build_result(
        self,
        detected: bool,
        confidence: ConfidenceLevel,
        matches: List[Dict[str, Any]],
        ai_confirmed: bool
    ) -> DetectionResult:
        """
        构建检测结果

        Args:
            detected: 是否检测到
            confidence: 置信度
            matches: 匹配列表
            ai_confirmed: AI是否确认

        Returns:
            DetectionResult
        """
        # 确定主要检测类型
        detection_type = DetectionType.UNKNOWN.value
        matched_text = None

        if matches:
            # 取第一个匹配作为主要类型
            detection_type = matches[0]["type"]
            matched_text = matches[0]["matched_text"]

        return DetectionResult(
            detected=detected,
            confidence=confidence.value,
            detection_type=detection_type,
            matched_text=matched_text,
            matches=matches,
            ai_confirmed=ai_confirmed,
            ai_analysis=None,
            processing_time_ms=0.0
        )

    def _get_cache_key(
        self,
        content: str,
        context: Optional[str],
        types: Optional[List[DetectionType]]
    ) -> str:
        """生成缓存键"""
        import hashlib
        content_hash = hashlib.md5(content.encode()).hexdigest()
        type_str = ",".join(t.value for t in types) if types else "all"
        return f"{content_hash}:{context or 'none'}:{type_str}"

    def _save_cache(self, key: str, result: DetectionResult):
        """保存到缓存"""
        if not self.enable_cache:
            return

        # LRU淘汰
        if len(self._cache) >= self._cache_max_size:
            # 删除最旧的一半
            keys_to_remove = list(self._cache.keys())[:self._cache_max_size // 2]
            for k in keys_to_remove:
                del self._cache[k]

        self._cache[key] = result

    def _get_type_description(self, type_value: str) -> str:
        """获取类型的中文描述"""
        descriptions = {
            DetectionType.FLAG.value: "CTF Flag",
            DetectionType.SQL_ERROR.value: "SQL错误信息",
            DetectionType.PATH_LEAK.value: "路径泄露",
            DetectionType.CREDENTIAL.value: "凭据信息",
            DetectionType.IP_ADDRESS.value: "IP地址",
            DetectionType.ERROR_MESSAGE.value: "错误信息",
            DetectionType.XSS.value: "XSS特征",
            DetectionType.LFI.value: "本地文件包含",
            DetectionType.RCE.value: "远程命令执行",
            DetectionType.UNKNOWN.value: "未知类型"
        }
        return descriptions.get(type_value, "安全相关信息")

    def _update_confidence_from_ai(
        self,
        result: DetectionResult,
        ai_response: str,
        quick_mode: bool
    ):
        """
        根据AI响应更新置信度

        Args:
            result: 检测结果
            ai_response: AI响应内容
            quick_mode: 是否快速模式
        """
        response_upper = ai_response.upper().strip()

        if quick_mode:
            # 快速模式：解析YES/NO/PARTIAL
            if response_upper.startswith("YES"):
                # AI确认，提升置信度
                if result["confidence"] == ConfidenceLevel.MEDIUM.value:
                    result["confidence"] = ConfidenceLevel.HIGH.value
                result["detected"] = True

            elif response_upper.startswith("NO"):
                # AI否认，降低置信度或标记为误报
                result["detected"] = False
                result["confidence"] = ConfidenceLevel.LOW.value

            elif response_upper.startswith("PARTIAL"):
                # 部分匹配，保持当前置信度
                pass

        else:
            # 深度分析模式：解析JSON
            try:
                import json
                # 尝试提取JSON
                json_start = ai_response.find("{")
                json_end = ai_response.rfind("}") + 1
                if json_start != -1 and json_end > json_start:
                    json_str = ai_response[json_start:json_end]
                    parsed = json.loads(json_str)

                    result["detected"] = parsed.get("detected", result["detected"])

                    # 更新类型
                    if "type" in parsed:
                        result["detection_type"] = parsed["type"]

                    # 更新置信度
                    if "confidence" in parsed:
                        result["confidence"] = parsed["confidence"]

            except (json.JSONDecodeError, ValueError):
                # JSON解析失败，保持原结果
                logger.debug(f"Failed to parse AI response as JSON: {ai_response[:100]}")

    def clear_cache(self):
        """清空缓存"""
        self._cache.clear()
        logger.info("Detection cache cleared")

    def get_statistics(self) -> Dict[str, Any]:
        """
        获取检测器统计信息

        Returns:
            统计信息字典
        """
        return {
            "cache_size": len(self._cache),
            "cache_max_size": self._cache_max_size,
            "high_confidence_patterns": len(self._compiled_high),
            "medium_confidence_patterns": len(self._compiled_medium),
            "ip_patterns": len(self._compiled_ip),
            "config": {
                "quick_confirm_timeout": self.quick_confirm_timeout,
                "deep_analysis_timeout": self.deep_analysis_timeout,
                "high_confidence_ai_verify": self.high_confidence_ai_verify,
                "enable_cache": self.enable_cache
            }
        }


# =============================================================================
# 便捷函数
# =============================================================================

# 全局检测器实例
_detector: Optional[HybridDetector] = None


def get_detector() -> HybridDetector:
    """获取全局检测器实例"""
    global _detector
    if _detector is None:
        _detector = HybridDetector(
            quick_confirm_timeout=15,
            deep_analysis_timeout=30,
            high_confidence_ai_verify=False
        )
    return _detector


def quick_detect(content: str) -> DetectionResult:
    """
    快速检测（仅正则，不调用AI）

    Args:
        content: 待检测文本

    Returns:
        检测结果
    """
    return get_detector().detect(content)


def full_detect(
    content: str,
    context: Optional[str] = None
) -> DetectionResult:
    """
    完整检测（正则+AI确认）

    Args:
        content: 待检测文本
        context: 上下文场景

    Returns:
        完整检测结果
    """
    return get_detector().detect_with_ai(content, context)


def check_flag(content: str) -> Optional[str]:
    """
    检查文本中是否包含FLAG

    Args:
        content: 待检查文本

    Returns:
        找到的FLAG字符串，未找到返回None
    """
    result = quick_detect(content)
    if result["detected"] and result["detection_type"] == DetectionType.FLAG.value:
        return result["matched_text"]
    return None


def check_sql_error(content: str) -> bool:
    """
    检查文本中是否包含SQL错误

    Args:
        content: 待检查文本

    Returns:
        是否检测到SQL错误
    """
    result = quick_detect(content)
    return result["detected"] and result["detection_type"] == DetectionType.SQL_ERROR.value


def check_credential(content: str) -> Optional[str]:
    """
    检查文本中是否包含凭据

    Args:
        content: 待检查文本

    Returns:
        找到的凭据字符串，未找到返回None
    """
    result = quick_detect(content)
    if result["detected"] and result["detection_type"] == DetectionType.CREDENTIAL.value:
        return result["matched_text"]
    return None