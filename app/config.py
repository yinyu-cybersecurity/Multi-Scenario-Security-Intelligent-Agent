# config.py - 系统全局配置
# 作用：所有阈值集中管理，方便调参
# 使用方式：from config import config
#
# 配置常量集中化：所有魔法值统一管理，每个常量有注释说明用途
from typing import List
from dataclasses import dataclass,field
import os
import yaml


@dataclass
class Config:
    """系统全局配置 - 支持从YAML文件加载
    使用方式:
        1. 直接修改这里的默认值
        2. 或创建config.yaml文件覆盖配置
        3. 运行时通过Config.from_yaml()加载

    配置热更新:
        修改yaml文件后，重启应用生效
    """

    # =========================================================================
    # 状态限制常量 - 用于防止内存溢出和数据膨胀
    # =========================================================================

    # 最大访问URL数（visited_urls 列表上限）
    # 超过此值后，旧记录会被丢弃
    MAX_VISITED_URLS: int = 100

    # 最大访问页面数（visited_fingerprints 列表上限）
    MAX_VISITED_PAGES: int = 100

    # 最大漏洞候选项（vuln_candidates 列表上限）
    # 分析兵发现的潜在漏洞最多保留10条
    MAX_VULN_CANDIDATES: int = 10

    # 最大攻击结果记录（attack_results 列表上限）
    # 保留最近的攻击结果用于反思分析
    MAX_ATTACK_RESULTS: int = 20

    # 最大工具调用记录（tool_calls 列表上限）
    # 主要用于调试，50条足够回溯
    MAX_TOOL_CALLS: int = 50

    # 最大失败payload记录（failed_payloads 列表上限）
    # 避免重复执行已失败的payload，30条足够
    MAX_FAILED_PAYLOADS: int = 30

    # 最大页面历史记录（page_history 字典键数上限）
    # 保留最近20个页面详情足够分析
    MAX_PAGE_HISTORY: int = 20

    # 最大已知凭据数（credentials 列表上限）
    MAX_CREDENTIALS: int = 30

    # 最大内网主机数（internal_hosts 列表上限）
    MAX_INTERNAL_HOSTS: int = 50

    # =========================================================================
    # 额外列表上限 - 防止无限增长
    # =========================================================================

    # 最大关键节点数（critical_nodes 列表上限）
    MAX_CRITICAL_NODES: int = 50

    # 最大攻击路径数（attack_paths 列表上限）
    MAX_ATTACK_PATHS: int = 20

    # 最大回退计划数（fallback_plans 列表上限）
    MAX_FALLBACK_PLANS: int = 20

    # 最大附件数（attachments 列表上限）
    MAX_ATTACHMENTS: int = 50

    # 最大活跃会话数（active_sessions 列表上限）
    MAX_ACTIVE_SESSIONS: int = 10

    # 最大已上传工具数（uploaded_tools 列表上限）
    MAX_UPLOADED_TOOLS: int = 30

    # 最大持久化结果数（persistence_results 列表上限）
    MAX_PERSISTENCE_RESULTS: int = 20

    # 最大已攻陷主机数（compromised_hosts 列表上限）
    MAX_COMPROMISED_HOSTS: int = 50

    # 最大发现Flag数（found_flags 列表上限）
    MAX_FOUND_FLAGS: int = 20

    # =========================================================================
    # 超时常量 - 所有超时相关配置
    # =========================================================================

    # 工具默认超时（秒）- 普通工具如 sqlmap
    TOOL_TIMEOUT_DEFAULT: int = 300  # 5分钟

    # 网络扫描超时（秒）- nmap/fscan 等慢速扫描
    TOOL_TIMEOUT_NETWORK: int = 600  # 10分钟

    # LLM调用超时（秒）
    LLM_TIMEOUT: int = 120  # 2分钟

    # 单个节点最大执行时间（秒）- 内网渗透可能很慢
    NODE_TIMEOUT: int = 1800  # 30分钟

    # 单个任务最大执行时间（秒）- Web CTF / 外网打点
    TASK_TIMEOUT: int = 1800  # 30分钟 (外网打点)

    # 内网渗透任务最大执行时间（秒）
    INTERNAL_TASK_TIMEOUT: int = 3000  # 50分钟 (内网渗透)

    # AI决策间隔（秒）- 每隔多久问一次AI是否继续
    DECISION_INTERVAL: int = 360  # 6分钟

    # 场景聚焦最大尝试次数
    MAX_SCENE_ATTEMPTS: int = 10  # 复杂漏洞需要更多尝试

    # =========================================================================
    # 重试常量 - 控制重试行为
    # =========================================================================

    # LLM调用重试次数
    LLM_RETRY_COUNT: int = 3

    # 工具执行重试次数
    TOOL_RETRY_COUNT: int = 2

    # LLM并发限制（同时进行的LLM请求数）
    # 需要容纳：analyst, attacker, verifier, router等多个节点的并发调用
    LLM_MAX_CONCURRENT: int = 10

    # =========================================================================
    # 决策阈值 - 控制模式切换（根据时间限制调整）
    # =========================================================================

    # 失败分达到此值进入探索模式（调高以匹配更长任务时间）
    FAILURE_SCORE_FOR_EXPLORE: float = 8.0

    # 失败分达到此值进入创新模式
    FAILURE_SCORE_FOR_INNOVATE: float = 15.0

    # 失败分达到此值放弃任务
    FAILURE_SCORE_ABANDON: float = 25.0

    # 规则引擎连续多少次没匹配到漏洞，强制进入创新模式
    RULE_MISS_FOR_INNOVATE: int = 8

    # 在探索模式至少尝试多少轮后，才允许进入创新模式
    EXPLORE_ROUNDS_FOR_INNOVATE: int = 8

    # 节点最大循环次数（防止死循环）
    MAX_LOOP_COUNT: int = 15

    # 无进展超时时间（秒）- 用于死循环检测
    NO_PROGRESS_TIMEOUT: int = 600  # 10分钟无进展视为卡死

    # 最大总运行轮次（防止无限烧Token，匹配30-50分钟任务时长）
    MAX_TOTAL_ROUNDS: int = 100

    # 步数达到此值自动进入创新模式
    MAX_STEPS_BEFORE_INNOVATE: int = 80

    # 是否启用AI模式决策（使用LLM决定模式切换）
    USE_AI_MODE_DECISION: bool = True

    # AI模式决策最小间隔（秒）- 避免频繁调用LLM
    AI_MODE_DECISION_INTERVAL: int = 120  # 2分钟

    # =========================================================================
    # Token 限制 - 控制上下文大小
    # =========================================================================

    # 触发压缩的Token阈值
    MAX_CONTEXT_TOKENS: int = 30000

    # Token估算因子（字符/token，中文约1.5，英文约4，代码约2-3）
    CHARS_PER_TOKEN: float = 2.5

    # =========================================================================
    # 任务完成验证配置 - 防止过早结束
    # =========================================================================

    # 是否启用AI完成验证
    AI_COMPLETION_VERIFICATION: bool = True

    # 最少Flag数量阈值（少于此值不结束）
    MIN_FLAGS_THRESHOLD: int = 1

    # 完成验证置信度阈值
    COMPLETION_CONFIDENCE_THRESHOLD: float = 0.7

    # 是否允许多Flag环境检测
    MULTI_FLAG_DETECTION: bool = True

    # 高价值节点未访问时不结束
    REQUIRE_HIGH_VALUE_VISITED: bool = True

    # 回退机制最大尝试次数
    BACKTRACK_MAX_ATTEMPTS: int = 3

    # 节点降权后保留时间（秒）
    DEPRIORITIZED_NODE_TTL: int = 600  # 10分钟

    # =========================================================================
    # 失败权重 - 用于计算 failure_weighted_score
    # =========================================================================

    # 404/403/500: 明显错误，权重高
    HARD_FAILURE_WEIGHT: float = 0.8

    # 200 OK但页面无变化: 可能是Payload无效，权重中
    SOFT_FAILURE_WEIGHT: float = 0.4

    # 200 OK且页面有变化但没Flag: 值得关注，权重低
    SUSPICIOUS_WEIGHT: float = 0.2

    # =========================================================================
    # 批处理配置
    # =========================================================================

    # 攻击兵每次生成的并发攻击动作数量
    BATCH_SIZE: int = 5

    # 并行Agent数量
    PARALLEL_AGENTS: int = 2

    # =========================================================================
    # 图数据库配置
    # =========================================================================

    # 最大探索深度
    GRAPH_MAX_DEPTH: int = 5

    # 剪枝状态码（遇到这些状态码的节点不继续探索）
    GRAPH_PRUNE_STATUS: List[int] = field(default_factory=lambda: [403, 404, 500])

    # 最大节点数
    GRAPH_MAX_NODES: int = 1000

    # 是否启用可视化
    GRAPH_ENABLE_VISUALIZATION: bool = False

    # =========================================================================
    # 页面变化检测配置
    # =========================================================================

    # 页面快照存储目录
    CACHE_DIR: str = "/tmp/ctf_cache"

    # 用于分析页面变化的轻量级模型
    CHANGE_DETECTION_MODEL: str = "deepseek-chat"

    # 变化检测置信度阈值
    CHANGE_DETECTION_CONFIDENCE: float = 0.8

    # 失败分调整策略
    SCORE_NO_CHANGE: float = 0.5              # MD5完全相同
    SCORE_CHANGE_NOT_EXPLOIT: float = 0.2     # MD5不同但非漏洞
    SCORE_CHANGE_EXPLOIT: float = 0.0         # 疑似漏洞利用成功

    # =========================================================================
    # 外带(OOB)配置
    # =========================================================================

    # 用于SSRF/XSS/RCE回连的服务器IP或域名
    OOB_HOST: str = "127.0.0.1"

    # =========================================================================
    # 内网渗透配置
    # 注意：框架直接运行在VPS服务器上
    # =========================================================================

    # 本机公网IP (框架运行的VPS的公网IP)
    LOCAL_PUBLIC_IP: str = ""

    # HTTP文件服务器端口
    HTTP_SERVER_PORT: int = 8000

    # 工具目录
    TOOLS_DIR: str = "/opt/tools"
    FRP_DIR: str = "/opt/frp"

    @property
    def HTTP_SERVER(self) -> str:
        """本机HTTP服务器地址"""
        if self.LOCAL_PUBLIC_IP:
            return f"http://{self.LOCAL_PUBLIC_IP}:{self.HTTP_SERVER_PORT}"
        return ""

    # frp目录
    FRP_DIR: str = "/opt/frp"

    # =========================================================================
    # 端口配置 - 各类服务端口列表
    # =========================================================================

    # Web服务端口
    WEB_PORTS: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000])

    # 数据库端口
    DATABASE_PORTS: List[int] = field(default_factory=lambda: [3306, 1433, 5432, 27017, 6379])

    # 域控/AD端口 (Kerberos, LDAP, LDAPS, Global Catalog)
    DOMAIN_CONTROLLER_PORTS: List[int] = field(default_factory=lambda: [88, 389, 636, 3268])

    # 文件服务端口 (SMB, FTP)
    FILE_SERVICE_PORTS: List[int] = field(default_factory=lambda: [445, 21])

    # 远程访问端口 (SSH, RDP, VNC)
    REMOTE_ACCESS_PORTS: List[int] = field(default_factory=lambda: [22, 3389, 5900])

    # 高价值端口 (域控+数据库+SMB)
    HIGH_VALUE_PORTS: List[int] = field(default_factory=lambda: [88, 389, 636, 3268, 1433, 3306, 5432, 445])

    # 邮件服务端口
    MAIL_PORTS: List[int] = field(default_factory=lambda: [21, 25, 110, 993, 995])

    # =========================================================================
    # 漏洞类型配置
    # =========================================================================

    # 已知漏洞类型列表
    VULN_TYPES: List[str] = field(default_factory=lambda: [
        "rce", "sqli", "xss", "lfi", "rfi", "ssrf", "xxe",
        "weak_password", "unauthorized", "deserialization",
        "ssti", "csrf", "file_upload", "command_injection"
    ])

    # Web漏洞类型 (用于URL绑定判断)
    WEB_VULN_TYPES: List[str] = field(default_factory=lambda: ["sqli", "xss", "lfi", "rce", "ssrf", "xxe"])

    # =========================================================================
    # HTTP请求配置
    # =========================================================================

    # HTTP HEAD请求超时(秒)
    HTTP_HEAD_TIMEOUT: int = 5

    # HTTP GET请求超时(秒)
    HTTP_GET_TIMEOUT: int = 10

    # =========================================================================
    # 工具配置
    # =========================================================================

    # 工具超时配置（秒）
    # 根据工具执行特点分级别设置超时时间
    TOOL_TIMEOUTS: dict = field(default_factory=lambda: {
        "default": 60,      # 默认超时
        "fast": 30,          # 快速工具（如简单请求）
        "normal": 60,        # 常规工具
        "slow": 180,         # 慢速工具（如扫描器）
        "very_slow": 300,    # 极慢工具（如深度扫描）
    })

    # 慢速工具列表（执行时间超过2分钟）
    # 这些工具会被自动分配更长的超时时间
    SLOW_TOOLS: List[str] = field(default_factory=lambda: [
        "dirsearch", "sqlmap", "nuclei", "fscan",
        "crackmapexec", "nmap", "hydra", "msf"
    ])

    # 扫描扩展名默认配置
    # 用于目录扫描、文件爆破等场景
    # 分层配置：基础层 + 配置层 + 数据层 + 备份层
    DEFAULT_SCAN_EXTENSIONS: str = (
        # 基础层：Web常见文件
        "php,html,htm,js,css,asp,aspx,jsp,do,action,"
        # 配置层：配置文件
        "json,xml,yaml,yml,conf,config,ini,env,properties,toml,"
        # 数据层：数据文件
        "sql,db,sqlite,csv,tsv,xls,xlsx,doc,docx,pdf,"
        # 备份层：备份和临时文件
        "bak,old,backup,swp,swo,tmp,save,copy,"
        # 源码层：版本控制和源码
        "git,svn,hg,htaccess,htpasswd,md,txt,log"
    )

    # 扩展探索工具组合
    # 多工具组合提升发现率
    EXPLORE_TOOLS: List[str] = field(default_factory=lambda: [
        "dirsearch",  # 目录扫描
        "ffuf",       # 模糊测试
        "nuclei",     # 漏洞扫描
        "httpx",      # HTTP探测
    ])

    # 并行扫描默认工具
    # 默认启用的自动化扫描工具组合
    DEFAULT_SCAN_TOOLS: List[str] = field(default_factory=lambda: ["nuclei", "xray"])

    # 基础手工工具
    # 手工测试和调试时常用的基础工具集
    BASIC_TOOLS: List[str] = field(default_factory=lambda: ["requests", "python-exec"])

    # 工具路径配置（支持环境变量覆盖）
    # Docker部署时可通过环境变量自定义路径
    TOOL_PATHS: dict = field(default_factory=lambda: {
        "thirdparty_base": os.environ.get("THIRDPARTY_BASE", "/app/thirdparty"),
        "wordlists": os.environ.get("WORDLISTS_PATH", "/app/data/security_resources/SecLists-master"),
        "data_dir": os.environ.get("DATA_DIR", "/app/data"),
    })

    # =========================================================================
    # LLM 配置
    # =========================================================================

    LLM_API_KEY: str = ""
    LLM_BASE_URL: str = "https://api.deepseek.com/v1"

    # =========================================================================
    # 模型配置

    # 未知漏洞置信度阈值
    # 如果漏洞类型不在已知规则中，但置信度达到此阈值，可能是新型漏洞或0day
    # 设置为 None 表示使用AI动态判断（需配合 analyze_vulnerability_novelty 函数）
    UNKNOWN_VULN_THRESHOLD: float = 0.8

    # 是否启用AI动态判断未知漏洞
    # True: 当未知漏洞置信度接近阈值时，使用AI进行二次判断
    # False: 使用固定的 UNKNOWN_VULN_THRESHOLD 阈值
    UNKNOWN_VULN_AI_JUDGEMENT: bool = False

    # 云/容器特征置信度提升值
    # 当检测到 cloud/docker/k8s 等特征时，对相关漏洞类型的置信度提升
    CLOUD_CONTAINER_CONFIDENCE_BOOST: float = 0.05

    # 中间件特征置信度提升值
    # 当检测到 tomcat/nginx/apache/redis/weblogic 等中间件特征时，对相关漏洞的置信度提升
    MIDDLEWARE_CONFIDENCE_BOOST: float = 0.2

    # 文件上传漏洞最低置信度
    # 当检测到 multipart/upload 特征时，文件上传漏洞的最低置信度保底值
    FILE_UPLOAD_MIN_CONFIDENCE: float = 0.6

    # 无技术栈时的降权系数
    # 当无法检测到任何技术栈时，对非通用漏洞的置信度乘以此系数
    NO_TECH_STACK_DOWNGRADE_FACTOR: float = 0.5

    # 无技术栈时的最低置信度保底值
    # 当无法检测技术栈时，非通用漏洞的置信度最低不会低于此值
    NO_TECH_STACK_MIN_CONFIDENCE: float = 0.1

    # 未知漏洞缺乏证据时的降权系数
    # 当未知漏洞置信度达标但缺乏具体证据时，置信度乘以此系数
    UNKNOWN_VULN_NO_EVIDENCE_DOWNGRADE_FACTOR: float = 0.6

    # 临时规则置信度提升值
    # 当漏洞匹配临时规则时，置信度提升
    TEMP_RULE_CONFIDENCE_BOOST: float = 0.2

    # =========================================================================
    # 模型配置 - 不同任务使用不同模型
    # =========================================================================

    # 分析兵：需要强推理能力
    ANALYST_MODEL: str = "deepseek-chat"

    # 攻击兵：需要代码生成能力
    ATTACKER_MODEL: str = "deepseek-chat"

    # 核验兵：需要长文本阅读能力
    VERIFIER_MODEL: str = "deepseek-chat"

    # 探索兵：需要处理大量日志
    EXPLORER_MODEL: str = "deepseek-chat"

    # 头脑风暴：需要极强的发散思维
    INNOVATOR_MODEL: str = "deepseek-chat"

    # =========================================================================
    # 上下文处理配置 - 针对大上下文模型优化
    # =========================================================================

    # 是否利用大上下文模型(128k+)处理完整HTML
    # True: 直接传完整HTML给AI提炼关键信息
    # False: 截断HTML到指定长度
    USE_LARGE_CONTEXT: bool = True

    # HTML截断长度(当USE_LARGE_CONTEXT=False时使用)
    HTML_TRUNCATE_LENGTH: int = 50000

    # 最大HTML处理长度(防止超限，即使大上下文也有限制)
    HTML_MAX_LENGTH: int = 100000

    @classmethod
    def from_yaml(cls, path: str = "config.yaml"):
        """从YAML文件加载配置

        Args:
            path: YAML配置文件路径

        Returns:
            Config: 配置对象
        """
        possible_paths = [
            path,
            os.path.join(os.path.dirname(__file__), '..', path),
            os.path.join(os.path.dirname(__file__), '..', '..', 'config.yaml'),
        ]

        for p in possible_paths:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                # 处理空文件或None情况
                if data is None:
                    data = {}
                return cls(**data)
        return cls()

    def validate(self) -> List[str]:
        """验证配置完整性

        Returns:
            错误消息列表，空列表表示验证通过
        """
        errors = []

        # LLM配置检查
        if not self.LLM_API_KEY:
            errors.append("LLM_API_KEY 未配置 - AI功能将无法使用")

        if not self.LLM_BASE_URL:
            errors.append("LLM_BASE_URL 未配置")

        # 内网渗透配置检查
        if self.LOCAL_PUBLIC_IP:
            # 如果设置了公网IP，检查端口配置
            if self.HTTP_SERVER_PORT <= 0 or self.HTTP_SERVER_PORT > 65535:
                errors.append(f"HTTP_SERVER_PORT 端口无效: {self.HTTP_SERVER_PORT}")

            if self.FRP_SERVER_PORT <= 0 or self.FRP_SERVER_PORT > 65535:
                errors.append(f"FRP_SERVER_PORT 端口无效: {self.FRP_SERVER_PORT}")

        # 阈值合理性检查
        if self.MAX_TOTAL_ROUNDS <= 0:
            errors.append(f"MAX_TOTAL_ROUNDS 必须大于0: {self.MAX_TOTAL_ROUNDS}")

        if hasattr(self, 'FAILURE_THRESHOLD') and self.FAILURE_THRESHOLD <= 0:
            errors.append(f"FAILURE_THRESHOLD 必须大于0: {self.FAILURE_THRESHOLD}")

        return errors

    def is_valid(self) -> bool:
        """检查配置是否有效"""
        return len(self.validate()) == 0


# 全局配置实例
config = Config.from_yaml()

# 启动时验证配置
_validation_errors = config.validate()
if _validation_errors:
    print("=" * 50)
    print("配置警告:")
    for err in _validation_errors:
        print(f"  - {err}")
    print("=" * 50)


# =============================================================================
# 工具配置辅助函数
# =============================================================================

def get_tool_timeout(tool_name: str) -> int:
    """根据工具名称获取超时时间

    Args:
        tool_name: 工具名称

    Returns:
        超时时间（秒）
    """
    if tool_name in config.SLOW_TOOLS:
        return config.TOOL_TIMEOUTS["slow"]
    return config.TOOL_TIMEOUTS["default"]


