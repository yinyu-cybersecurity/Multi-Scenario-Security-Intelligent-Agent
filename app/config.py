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
    LLM_MAX_CONCURRENT: int = 5

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

    # 最大总运行轮次（防止无限烧Token，匹配30-50分钟任务时长）
    MAX_TOTAL_ROUNDS: int = 100

    # 步数达到此值自动进入创新模式
    MAX_STEPS_BEFORE_INNOVATE: int = 80

    # =========================================================================
    # Token 限制 - 控制上下文大小
    # =========================================================================

    # 触发压缩的Token阈值
    MAX_CONTEXT_TOKENS: int = 30000

    # Token估算因子（字符/token，中文约1.5，英文约4，代码约2-3）
    CHARS_PER_TOKEN: float = 2.5

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

    # frp配置
    FRP_SERVER_PORT: int = 7000
    FRP_SOCKS5_PORT: int = 10800

    # =========================================================================
    # LLM 配置
    # =========================================================================

    LLM_API_KEY: str = ""
    LLM_BASE_URL: str = "https://api.deepseek.com/v1"

    # =========================================================================
    # RAG配置
    # =========================================================================

    RAG_ENABLED: bool = True
    RAG_FOR_WEB_ONLY: bool = True

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
            os.path.join(os.path.dirname(__file__), '..', '..', path),
        ]

        for p in possible_paths:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
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