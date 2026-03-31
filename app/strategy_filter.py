# strategy_filter.py - 策略过滤器
# 作用：根据技术栈过滤漏洞候选，防止LLM生成不匹配的攻击

import json
from typing import Dict, Tuple, Optional
from logger import get_logger
from state_v2 import CTFState
from config import config
from llm_client import safe_call_chat_completion

logger = get_logger("Strategy")


class TechStackRules:
    """技术栈-漏洞类型映射规则
    这些规则决定了什么技术栈可能有什么漏洞
    """

    # 1. 规范化映射字典 (解决大模型命名不一致问题)
    NORMALIZED_NAMES = {
        "sql_injection": "sqli",
        "directory_traversal": "arbitrary_file_read",
        "path_traversal": "arbitrary_file_read",
        "xxe_injection": "xxe"
    }

    # 2. 通用漏洞（所有环境允许，含API与协议层）
    UNIVERSAL_ALLOWED = [
        "race_condition",  # 条件竞争 (2024+ Single-Packet Attacks)
        "http_smuggling",  # HTTP请求走私 (含HTTP/2 Downgrade变种)
        "idor",            # 未授权访问
        "api_abuse",       # API滥用
        "logic_flaw",      # 逻辑漏洞
        "weak_password",   # 弱口令
        "info_leak",       # 信息泄露
        "cors_misconfig",  # CORS配置错误
        "websocket_vuln",  # WebSocket漏洞
        "ws_message_injection", # WebSocket消息注入
        "ws_origin_bypass",     # WebSocket Origin绕过
        "graphql_injection", # GraphQL注入
        "graphql_introspection", # GraphQL内省查询
        "graphql_batching",      # GraphQL批处理攻击
        "jwt_vuln",        # JWT弱密钥/算法混淆
        "jwt_none_algorithm", # JWT None算法
        "jwt_kid_injection",  # JWT KID注入
        "jwt_jku_spoofing",   # JWT JKU伪造
        "mass_assignment", # 批量赋值
        "crlf_injection",  # CRLF注入
        "dns_rebinding",   # DNS重绑定
        "arbitrary_file_read", # 通用任意文件读取 (区分于能直接RCE的LFI)
        "ssrf",            # SSRF
        "xss",             # XSS
        "svg_xss",         # 恶意SVG图片XSS
        "sqli",            # SQL注入
        "command_injection", # 命令注入
    ]

    # 3. 云原生与容器化
    CLOUD_CONTAINER_ALLOWED = [
        "docker_escape",       # 容器逃逸
        "k8s_rce",             # K8s API未授权/RCE
        "ssrf_cloud_metadata", # 云元数据窃取 (169.254.169.254)
        "env_var_leak",        # 环境变量泄露
    ]

    # 4. 中间件与服务器
    MIDDLEWARE_ALLOWED = [
        "nginx_alias_traversal",     # Nginx配置不当导致的穿越
        "apache_path_normalization", # Apache路径解析差异
        "apache_newline_parsing",    # CVE-2017-15715 换行解析漏洞
        "apache_mod_cgi",            # Apache CGI RCE
        "apache_confusion_attack",   # Apache Confusion Attacks (BlackHat 2024)
        "redis_ssrf_rce",            # 通过SSRF打Redis (主从复制/写Cron)
        "redis_cron_write",          # Redis写计划任务
        "tomcat_ghostcat",           # AJP文件读取 (CVE-2020-1938)
        "tomcat_manager_deploy",     # Tomcat弱口令+部署WAR
        "weblogic_deserialize",      # WebLogic 反序列化
        "iis_shortname",             # IIS 短文件名泄露
    ]

    # AI与大模型安全 (AI Security)
    AI_SECURITY_ALLOWED = [
        "prompt_injection",    # 提示词注入
        "model_poisoning",     # 模型投毒
        "agent_tool_abuse",    # Agent工具滥用
        "llm_dos",             # 上下文耗尽DoS
    ]

    # 6. 内存安全语言 (Go/Rust) - 2025+ 趋势
    MEMORY_SAFE_LANGS_ALLOWED = [
        "go_template_injection",   # Go SSTI
        "rust_template_injection", # Rust SSTI (Tera/Askama)
        "gob_deserialize",         # Go Gob反序列化
        "regex_dos",               # ReDoS (通用但Go/Rust常考)
        "go_unsafe_pointer",       # Go Unsafe Pointer滥用
    ]
    
    
    # PHP环境允许的漏洞类型
    PHP_ALLOWED = [
        "lfi",               # 本地文件包含 (PHP特有，可转RCE)
        "rfi",               # 远程文件包含
        "file_upload",       # 文件上传
        "php_filter_chain",  # PHP Filter Chain (Oracle Attack)
        "phar_deserialize",  # PHAR反序列化
        "phar_zip_wrapper",  # PHAR配合Zip包装器
        "session_upload_progress", # PHP Session条件竞争
        "pearcmd_rce",       # Pearcmd.php 命令行调用
        "php_weak_type",     # 弱类型比较/Hash碰撞
        "php_info",          # PHPINFO信息泄露
        "php_deserialize",   # PHP反序列化
        "pop_chain",         # POP链利用
        "uaf_php8",          # PHP 8 UAF
    ]

    # PHP环境禁止的漏洞类型
    PHP_BLOCKED = [
        "log4j", "ognl", "jsp_code_exec", "jndi", "spring4shell", 
        "python_class_pollution", "ssti_jinja2", "pickle_deserialize",
        "prototype_pollution", "vm_escape"
    ]

    # Java环境允许的漏洞类型
    JAVA_ALLOWED = [
        "log4j", "ognl", "jndi", "spring4shell", "jsp_code_exec",
        "deserialize_java", "jackson_deserialize", "fastjson_deserialize", 
        "spel_injection", "groovy_code_exec", "spring_cloud_function_rce",
        "jackson_polymorphic"
    ]

    # Java环境禁止的漏洞类型
    JAVA_BLOCKED = [
        "php_filter_chain", "phar_deserialize", "file_upload_php", 
        "ssti_jinja2", "python_class_pollution", "pickle_deserialize",
        "prototype_pollution", "node_require_lfi"
    ]

    # Node.js环境允许的漏洞类型
    NODE_ALLOWED = [
        "prototype_pollution", "ejs_injection", "express_template_injection",
        "nosqli", "vm_escape", "vm2_escape", "node_require_lfi", 
        "npm_script_injection"
    ]

    # Node.js环境禁止的漏洞类型
    NODE_BLOCKED = [
        "php_filter_chain", "phar_deserialize", "log4j", "ognl", 
        "jsp_code_exec", "pickle_deserialize", "python_class_pollution",
        "ssti_jinja2", "deserialize_java"
    ]

    # Python环境允许的漏洞类型
    PYTHON_ALLOWED = [
        "ssti_jinja2", "ssti_mako", "ssti_tornado", "jinja2_sandbox_escape",
        "python_deserialize", "pickle_deserialize", "yaml_deserialize",
        "python_class_pollution", "asyncio_injection",
        "flask_session_forge", # Flask Session伪造
        "python_memory_shell", # Python内存马 (Bottle/Flask)
    ]

    # Python环境禁止的漏洞类型
    PYTHON_BLOCKED = [
        "php_filter_chain", "phar_deserialize", "log4j", "ognl",
        "jsp_code_exec", "prototype_pollution", "deserialize_java"
    ]

    # 未知漏洞处理机制 (Unknown Vulnerability Handling)
    # 如果漏洞类型不在上述任何列表中，但置信度极高，可能是新型漏洞或0day
    # 允许通过的置信度阈值已移至 config.py 的 UNKNOWN_VULN_THRESHOLD 配置

    # 聚合所有已知规则，用于判断是否为"未知"
    ALL_KNOWN_TYPES = set(UNIVERSAL_ALLOWED + CLOUD_CONTAINER_ALLOWED + MIDDLEWARE_ALLOWED +
                          AI_SECURITY_ALLOWED + MEMORY_SAFE_LANGS_ALLOWED +
                          PHP_ALLOWED + JAVA_ALLOWED + NODE_ALLOWED + PYTHON_ALLOWED +
                          PHP_BLOCKED + JAVA_BLOCKED + NODE_BLOCKED + PYTHON_BLOCKED)


def _ai_judge_unknown_vulnerability(
    candidate: Dict,
    tech_stack: list,
    page_features: Dict
) -> Tuple[bool, float, str]:
    """
    使用AI判断未知漏洞是否为真实漏洞

    当漏洞类型不在已知规则中，但置信度接近阈值时，调用AI进行二次判断。

    Args:
        candidate: 漏洞候选字典，包含type, confidence, context, location等字段
        tech_stack: 检测到的技术栈列表
        page_features: 页面特征字典

    Returns:
        Tuple[bool, float, str]: (是否保留, 调整后的置信度, 判断理由)
    """
    vuln_type = candidate.get("type", "unknown")
    confidence = candidate.get("confidence", 0)
    context = candidate.get("context", {})
    location = candidate.get("location", "")

    # 构建上下文证据描述
    evidence_parts = []
    if isinstance(context, dict):
        for key in ["evidence", "proof", "payload", "code_snippet", "stack_trace", "error_message"]:
            if key in context:
                evidence_parts.append(f"- {key}: {context[key]}")

    # 技术栈匹配度分析
    tech_str = " ".join(tech_stack).lower() if tech_stack else ""
    tech_info = context.get("tech", "") if isinstance(context, dict) else ""
    if isinstance(tech_info, list):
        tech_info = " ".join(tech_info)

    # 构建AI判断Prompt
    prompt = f"""你是一位安全专家，需要判断一个潜在的未知漏洞类型是否值得进一步探索。

## 漏洞信息
- 漏洞类型: {vuln_type}
- 初始置信度: {confidence}
- 位置: {location or '未指定'}

## 上下文证据
{chr(10).join(evidence_parts) if evidence_parts else '- 无具体证据'}

## 技术栈信息
- 检测到的技术栈: {tech_str or '未检测到'}
- 漏洞关联的技术: {tech_info or '未指定'}

## 判断标准
请综合考虑以下因素判断该漏洞是否值得探索：

1. **漏洞特征合理性** (权重40%)
   - 漏洞类型命名是否反映真实的攻击模式
   - 是否是已知漏洞类型的变体或组合
   - 是否符合常见漏洞分类体系（如CWE）

2. **上下文证据强度** (权重30%)
   - 是否有具体的payload、代码片段或错误信息
   - 位置描述是否精确（如包含参数名、路径）
   - 证据是否能支撑该漏洞类型

3. **技术栈匹配度** (权重30%)
   - 漏洞类型是否与检测到的技术栈兼容
   - 是否存在技术栈冲突（如PHP环境出现Java漏洞）
   - 技术栈信息是否足够支持判断

## 输出格式
请以JSON格式输出判断结果：
{{
    "should_explore": true/false,
    "adjusted_confidence": 0.0-1.0之间的数值,
    "reason": "简要说明判断理由（中文，50字以内）",
    "risk_level": "high/medium/low",
    "key_factors": ["因素1", "因素2"]
}}

注意：
- 如果技术栈与漏洞类型严重冲突（如纯静态站点出现SQL注入），adjusted_confidence应降低至0.1以下
- 如果有强证据支撑（如具体payload、错误回显），adjusted_confidence可保持或提升
- 如果完全缺乏证据且技术栈不明确，建议保守判断，adjusted_confidence降至0.3以下
- should_explore为false时，该漏洞将被过滤掉"""

    try:
        # 调用LLM进行判断
        response = safe_call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            json_mode=True,
            timeout=30
        )

        if not response:
            logger.warning(f"  AI判断未知漏洞失败: LLM返回空响应")
            return False, confidence * 0.5, "AI判断失败，保守降权"

        # 解析JSON响应
        result = json.loads(response)

        should_explore = result.get("should_explore", False)
        adjusted_confidence = result.get("adjusted_confidence", confidence)
        reason = result.get("reason", "未提供理由")
        risk_level = result.get("risk_level", "unknown")

        # 确保置信度在有效范围内
        adjusted_confidence = max(0.0, min(1.0, float(adjusted_confidence)))

        logger.info(f"  AI判断结果: {vuln_type} -> should_explore={should_explore}, "
                   f"confidence={adjusted_confidence:.2f}, risk={risk_level}, reason={reason}")

        return should_explore, adjusted_confidence, reason

    except json.JSONDecodeError as e:
        logger.warning(f"  AI判断未知漏洞失败: JSON解析错误 - {e}")
        return False, confidence * 0.5, "JSON解析失败"

    except Exception as e:
        logger.warning(f"  AI判断未知漏洞异常: {e}")
        return False, confidence * 0.5, f"判断异常: {str(e)}"


def strategy_filter_node(state: CTFState) -> Dict:
    """
    策略过滤器 - 纯代码逻辑，防止LLM降智攻击

    执行流程：
        1. 获取漏洞候选列表
        2. 获取页面特征（技术栈）
        3. 根据技术栈过滤不匹配的漏洞
        4. 应用临时规则提升某些漏洞的优先级
        5. 按置信度排序

    Args:
        state: 当前状态

    Returns:
        更新后的漏洞候选列表
    """
    logger.info(" [StrategyFilter] 过滤策略...")

    # 获取漏洞候选列表
    candidates = state.get("vuln_candidates", [])
    if not candidates:
        return {}

    # 获取页面特征和技术栈
    features = state.get("page_features") or {}  # [防御性修复] 处理 None 值
    tech_stack = features.get("tech_stack", [])

    # 获取临时规则（来自头脑风暴）
    temp_rules = state.get("temp_rules", [])

    filtered = []

    # ===== 核心过滤逻辑 =====
    for cand in candidates:
        raw_type = cand.get("type", "")
        # 1. 漏洞类型标准化映射
        cand_type = TechStackRules.NORMALIZED_NAMES.get(raw_type.lower(), raw_type)
        cand["type"] = cand_type

        # 合并所有的技术栈特征用于联合判断
        tech_info = cand.get("context", {}).get("tech", "")
        if isinstance(tech_info, list):
            tech_info = " ".join(tech_info)
        tech_str = (str(tech_info) + " " + " ".join(tech_stack)).lower()

        keep = True

        # 2. 动态特征权重提升 (环境指纹)
        # Cloud/Container - 降级处理，避免误判
        if any(kw in tech_str for kw in ["cloud", "aws", "aliyun", "docker", "k8s", "kubernetes"]):
            if cand_type in TechStackRules.CLOUD_CONTAINER_ALLOWED:
                cand["confidence"] = min(1.0, cand.get("confidence", 0) + config.CLOUD_CONTAINER_CONFIDENCE_BOOST) # CTF中Docker通常只是环境
                # print(f" 检测到云/容器特征，提升 {cand_type} 优先级")
        
        # Middleware Fingerprinting (解决中间件误杀)
        middleware_vuln_map = {
            "tomcat": ["tomcat_ghostcat", "tomcat_manager_deploy"],
            "nginx": ["nginx_alias_traversal"],
            "apache": ["apache_path_normalization", "apache_newline_parsing", "apache_mod_cgi", "apache_confusion_attack"],
            "redis": ["redis_ssrf_rce", "redis_cron_write"],
            "weblogic": ["weblogic_deserialize"]
        }
        for mw, vulns in middleware_vuln_map.items():
            if mw in tech_str and cand_type in vulns:
                cand["confidence"] = min(1.0, cand.get("confidence", 0) + config.MIDDLEWARE_CONFIDENCE_BOOST)
                logger.info(f"  检测到中间件 {mw} 特征，保留并提升 {cand_type}")
                keep = True

        # 3. Payload原语提示
        payload_hint = ""
        if cand_type == "arbitrary_file_read":
            if "php" in tech_str: payload_hint = "include, file_get_contents, readfile"
            elif "java" in tech_str: payload_hint = "Files.readString, Class.getResourceAsStream"
            elif "python" in tech_str: payload_hint = "open(), file.read()"
            elif "node" in tech_str: payload_hint = "fs.readFile, fs.readFileSync"
        elif cand_type == "command_injection" or cand_type == "rce":
            if "php" in tech_str: payload_hint = "system, exec, passthru, shell_exec"
            elif "java" in tech_str: payload_hint = "Runtime.exec, ProcessBuilder"
            elif "python" in tech_str: payload_hint = "os.system, subprocess.Popen, os.popen"
            elif "node" in tech_str: payload_hint = "child_process.exec, child_process.spawn"
        elif cand_type == "ssrf":
            if "php" in tech_str: payload_hint = "curl, file_get_contents, fsockopen"
            elif "java" in tech_str: payload_hint = "HttpURLConnection, HttpClient, ImageIO"
            elif "python" in tech_str: payload_hint = "requests.get, urllib.urlopen"
        
        if payload_hint:
            cand.setdefault("context", {})["payload_hint"] = payload_hint

        # 4. 组合链入口保留 (Chain Gadget Preservation)
        # 只要有上传入口，强制保留 file_upload，无论置信度
        if cand_type == "file_upload" and ("multipart" in tech_str or "upload" in tech_str):
            cand["confidence"] = max(config.FILE_UPLOAD_MIN_CONFIDENCE, cand.get("confidence", 0))
            keep = True

        # 5. 分类过滤逻辑
        # 如果没有检测到任何技术栈，采取保守策略：保留但降权，而不是直接杀掉
        if not tech_stack and not tech_info:
             if cand_type not in TechStackRules.UNIVERSAL_ALLOWED:
                 cand["confidence"] = max(config.NO_TECH_STACK_MIN_CONFIDENCE, cand.get("confidence", 0) * config.NO_TECH_STACK_DOWNGRADE_FACTOR)
                 pass 
        
        # 6. 未知漏洞豁免机制 (High-Confidence Anomaly Exemption) & 证据驱动校验
        # 如果是规则库里完全没有记录的漏洞类型，但LLM给出了极高置信度，放行
        elif cand_type not in TechStackRules.ALL_KNOWN_TYPES:
            # 证据驱动：检查是否有具体的上下文证据
            has_evidence = False
            ctx = cand.get("context", {})
            if isinstance(ctx, dict) and any(k in ctx for k in ["evidence", "proof", "payload", "code_snippet", "stack_trace"]):
                has_evidence = True

            # 检查位置是否具体
            loc = cand.get("location", "")
            is_specific_loc = ":" in loc or "=" in loc

            # 判断是否启用AI二次判断
            if config.UNKNOWN_VULN_AI_JUDGEMENT:
                # 使用AI进行二次判断
                logger.info(f"  未知漏洞 {cand_type} 触发AI二次判断...")
                should_keep, adjusted_conf, reason = _ai_judge_unknown_vulnerability(
                    cand, tech_stack, features
                )
                cand["confidence"] = adjusted_conf
                cand["ai_judgement"] = {
                    "passed": should_keep,
                    "reason": reason,
                    "original_confidence": cand.get("confidence", 0)
                }

                if should_keep:
                    logger.info(f"  AI判断通过: {cand_type} (置信度: {adjusted_conf:.2f}) - {reason}")
                    pass  # keep = True
                else:
                    logger.info(f"  AI判断拒绝: {cand_type} - {reason}")
                    keep = False
            else:
                # 使用原有固定阈值逻辑
                if cand.get("confidence", 0) >= config.UNKNOWN_VULN_THRESHOLD:
                    if has_evidence or is_specific_loc:
                        logger.info(f"  检测到高置信度未知漏洞 {cand_type} (Confidence: {cand.get('confidence')}) - 证据确凿，强制保留！")
                        pass # keep = True
                    else:
                        logger.info(f"  未知漏洞 {cand_type} 置信度高但缺乏证据 - 降权保留")
                        cand["confidence"] *= config.UNKNOWN_VULN_NO_EVIDENCE_DOWNGRADE_FACTOR
                        pass
                else:
                    # 置信度不够高的未知漏洞，大概率是幻觉
                    # print(f"  过滤低置信度未知漏洞 {cand_type}")
                    keep = False

        elif (cand_type in TechStackRules.UNIVERSAL_ALLOWED or 
            cand_type in TechStackRules.CLOUD_CONTAINER_ALLOWED or 
            cand_type in TechStackRules.MIDDLEWARE_ALLOWED or
            cand_type in TechStackRules.AI_SECURITY_ALLOWED or
            cand_type in TechStackRules.MEMORY_SAFE_LANGS_ALLOWED):
            # 通用、云原生、中间件、AI、Go/Rust类漏洞，直接放行
            pass
        else:
            # 语言级严格过滤
            if "php" in tech_str and cand_type in TechStackRules.PHP_BLOCKED:
                logger.info(f"  过滤PHP环境下的 {cand_type}")
                keep = False
            elif "java" in tech_str and cand_type in TechStackRules.JAVA_BLOCKED:
                logger.info(f"  过滤Java环境下的 {cand_type}")
                keep = False
            elif ("node" in tech_str or "javascript" in tech_str) and cand_type in TechStackRules.NODE_BLOCKED:
                logger.info(f"  过滤Node环境下的 {cand_type}")
                keep = False
            elif "python" in tech_str and cand_type in TechStackRules.PYTHON_BLOCKED:
                logger.info(f"  过滤Python环境下的 {cand_type}")
                keep = False

        # 临时规则优先级提升
        for rule in temp_rules:
            rule_condition = rule.get("condition", "")
            if rule_condition in cand_type or rule_condition in tech_str:
                # 提升置信度，但不超过1.0
                cand["confidence"] = min(1.0, cand.get("confidence", 0) + config.TEMP_RULE_CONFIDENCE_BOOST)
                logger.info(f"  临时规则提升 {cand_type} 优先级")

        if keep:
            filtered.append(cand)

    # 按置信度从高到低排序
    filtered.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    logger.info(f"[StrategyFilter] 过滤前 {len(candidates)} 个，过滤后 {len(filtered)} 个")

    return {"vuln_candidates": filtered}