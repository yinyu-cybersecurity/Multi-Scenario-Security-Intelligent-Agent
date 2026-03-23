# config.py - 系统全局配置
# 作用：所有阈值集中管理，方便调参
# 使用方式：from config import Config
from typing import List
from dataclasses import dataclass, field
import os
import yaml


@dataclass
class Config:
    """系统全局配置 - 支持从YAML文件加载"""

    # ===== 任务熔断配置 =====
    # 单个任务最大执行时间（秒），20分钟
    TASK_TIMEOUT: int = 1200

    # ===== 系统控制 =====
    # 最大总运行轮次，大幅提高
    MAX_TOTAL_ROUNDS: int = 500

    # 最大记录页面数
    MAX_VISITED_PAGES: int = 200

    # 漏洞候选队列最大长度
    MAX_VULN_CANDIDATES: int = 20

    # ===== 模式切换阈值 =====
    # 失败分达到此值进入探索模式（大幅提高）
    FAILURE_SCORE_FOR_EXPLORE: float = 20.0

    # 失败分达到此值进入创新模式（大幅提高）
    FAILURE_SCORE_FOR_INNOVATE: float = 40.0

    # 在探索模式至少尝试多少轮后，才允许进入创新模式
    EXPLORE_ROUNDS_FOR_INNOVATE: int = 20

    # 规则引擎连续多少次没匹配到漏洞，强制进入创新模式
    RULE_MISS_FOR_INNOVATE: int = 15

    # ===== 失败权重 =====
    HARD_FAILURE_WEIGHT: float = 0.5
    SOFT_FAILURE_WEIGHT: float = 0.3
    SUSPICIOUS_WEIGHT: float = 0.1

    # ===== 批处理配置 =====
    BATCH_SIZE: int = 5
    PARALLEL_AGENTS: int = 2

    # ===== 图数据库配置 =====
    GRAPH_MAX_DEPTH: int = 8
    GRAPH_PRUNE_STATUS: List[int] = field(default_factory=lambda: [404, 500])
    GRAPH_MAX_NODES: int = 2000
    GRAPH_ENABLE_VISUALIZATION: bool = False

    # ===== 页面变化检测配置 =====
    CACHE_DIR: str = "/tmp/ctf_cache"
    CHANGE_DETECTION_MODEL: str = "deepseek-chat"
    CHANGE_DETECTION_CONFIDENCE: float = 0.8
    SCORE_NO_CHANGE: float = 0.3
    SCORE_CHANGE_NOT_EXPLOIT: float = 0.1
    SCORE_CHANGE_EXPLOIT: float = 0.0

    # ===== 外带(OOB)配置 =====
    OOB_HOST: str = "127.0.0.1"

    # ===== LLM 配置 =====
    LLM_API_KEY: str = "sk-9b037d6ba1314ba48c858c530bd70b09"
    LLM_BASE_URL: str = "https://api.deepseek.com/v1"

    # ===== 模型配置 =====
    ANALYST_MODEL: str = "deepseek-chat"
    ATTACKER_MODEL: str = "deepseek-chat"
    VERIFIER_MODEL: str = "deepseek-chat"
    EXPLORER_MODEL: str = "deepseek-chat"
    INNOVATOR_MODEL: str = "deepseek-chat"

    # ===== RAG配置 =====
    RAG_ENABLED: bool = True
    RAG_FOR_WEB_ONLY: bool = True  # 只在Web CTF场景使用RAG

    @classmethod
    def from_yaml(cls, path: str = "config.yaml"):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            return cls(**data)
        return cls()


config = Config.from_yaml()