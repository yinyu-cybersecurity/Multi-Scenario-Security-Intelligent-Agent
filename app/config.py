# config.py - 系统全局配置
# 作用：所有阈值集中管理，方便调参
# 使用方式：from config import Config
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

    # ===== 模式切换阈值 =====
    # 失败分达到此值进入探索模式
    FAILURE_SCORE_FOR_EXPLORE: float = 5.0  # [上调] 原2.0，给攻击更多机会

    # 失败分达到此值进入创新模式
    FAILURE_SCORE_FOR_INNOVATE: float = 10.0  # [上调] 原5.0，让攻击更充分

    # 在探索模式至少尝试多少轮后，才允许进入创新模式
    EXPLORE_ROUNDS_FOR_INNOVATE: int = 5

    # 规则引擎连续多少次没匹配到漏洞，强制进入创新模式
    RULE_MISS_FOR_INNOVATE: int = 5

    # ===== 系统控制 =====
    # 最大总运行轮次，防止无限烧Token
    MAX_TOTAL_ROUNDS: int = 60

    # 最大记录页面数，防止内存溢出
    MAX_VISITED_PAGES: int = 60

    # 漏洞候选队列最大长度
    MAX_VULN_CANDIDATES: int = 10

    # ===== 节点熔断配置 =====
    # 单个节点的最大攻击时间（秒），超时强制放弃
    NODE_TIMEOUT: int = 1800  # 30分钟

    # AI决策间隔（秒），每隔多久问一次AI是否继续
    DECISION_INTERVAL: int = 360  # 6分钟

    # ===== 失败权重 =====
    # 404/403/500: 明显错误，权重高
    HARD_FAILURE_WEIGHT: float = 0.8

    # 200 OK但页面无变化: 可能是Payload无效，权重中
    SOFT_FAILURE_WEIGHT: float = 0.4

    # 200 OK且页面有变化但没Flag: 值得关注，权重低
    SUSPICIOUS_WEIGHT: float = 0.2

    # ===== 批处理配置 =====
    # 攻击兵每次生成的并发攻击动作数量
    BATCH_SIZE: int = 5

    # 并行Agent数量（2个LLM + 规则引擎）
    PARALLEL_AGENTS: int = 2

    # ===== 图数据库配置 =====
    GRAPH_MAX_DEPTH: int = 5  # 最大探索深度
    GRAPH_PRUNE_STATUS: List[int] = field(default_factory=lambda: [403, 404, 500])  # 剪枝状态码
    GRAPH_MAX_NODES: int = 1000  # 最大节点数
    GRAPH_ENABLE_VISUALIZATION: bool = False  # 是否启用可视化



    # ===== 页面变化检测配置 =====
    # 页面快照存储目录（用于基线对比）
    CACHE_DIR: str = "/tmp/ctf_cache"
    
    # 用于分析页面变化的轻量级模型
    CHANGE_DETECTION_MODEL: str = "deepseek-chat"
    
    # 变化检测置信度阈值（超过此值才视为有效攻击）
    CHANGE_DETECTION_CONFIDENCE: float = 0.8
    
    # 失败分调整策略（用于智能体进化）
    SCORE_NO_CHANGE: float = 0.5       # MD5完全相同（攻击无效）
    SCORE_CHANGE_NOT_EXPLOIT: float = 0.2  # MD5不同但非漏洞（如动态内容变化）
    SCORE_CHANGE_EXPLOIT: float = 0.0      # 疑似漏洞利用成功（不扣分，甚至奖励）

    # ===== 外带(OOB)配置 =====
    # 外带(OOB)配置
    # 用于SSRF/XSS/RCE回连的服务器IP或域名
    # 会替换Payload中的 {{OOB_HOST}}
    OOB_HOST: str = "127.0.0.1"

    # ===== LLM 配置 =====
    LLM_API_KEY: str = "sk-9b037d6ba1314ba48c858c530bd70b09"
    LLM_BASE_URL: str = "https://api.deepseek.com/v1"

    # ===== HITL & 熔断配置 =====
    # 触发人工介入的步数上限
    MAX_STEPS_BEFORE_HITL: int = 50  # [上调] 原40，给AI更多尝试
    # 触发人工介入的失败分阈值
    HITL_FAILURE_SCORE: float = 15.0  # [上调] 原8.0，更晚触发人工

    # ===== 模型配置 =====
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

    @classmethod
    def from_yaml(cls, path: str = "config.yaml"):
        """从YAML文件加载配置

        如果配置文件存在，则加载并覆盖默认值；
        如果不存在，则使用默认配置。

        Args:
            path: YAML配置文件路径

        Returns:
            Config: 配置对象
        """
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            return cls(**data)
        return cls()


# ===== 全局配置实例 =====
# 其他地方使用：from config import config
config = Config.from_yaml()