# logger.py
"""
统一日志系统

特性:
- 控制台输出简练关键信息
- 文件记录完整日志
- 按任务ID分目录存储
- 按节点分文件记录
- 支持查看全流程/各兵种日志

使用方式:
    from logger import get_logger, TaskLogger
    logger = get_logger(__name__)
    logger.info("信息日志")

    # 任务日志
    task_logger = TaskLogger(task_id)
    task_logger.node_log("attacker", "攻击成功")
"""

import logging
import sys
import os
import json
from datetime import datetime
from typing import Optional, Dict
from pathlib import Path


# 日志格式
CONSOLE_FORMAT = "%(message)s"  # 控制台简洁格式
FILE_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%H:%M:%S"

# 颜色代码
COLORS = {
    'DEBUG': '\033[36m',
    'INFO': '\033[32m',
    'WARNING': '\033[33m',
    'ERROR': '\033[31m',
    'CRITICAL': '\033[35m',
    'RESET': '\033[0m'
}

# 节点图标映射
NODE_ICONS = {
    'recon': '🔍',
    'analyst': '📊',
    'attacker': '⚔️',
    'verifier': '✅',
    'explorer': '🗺️',
    'innovator': '💡',
    'evolution': '📈',
    'mode_manager': '🔀',
    'strategy_filter': '🎯',
    'post_exploit': '🔓',
    'internal_recon': '🌐',
    'lateral_move': '➡️',
    'privilege_escalation': '⬆️',
    'credential_gather': '🔑',
    'default': '📋'
}


class ConsoleFormatter(logging.Formatter):
    """控制台简洁格式化器"""

    def __init__(self):
        super().__init__()
        # 检测控制台是否支持UTF-8/emoji
        self._supports_utf8 = self._check_utf8_support()
        self._safe_icons = self._get_safe_icons()

    def _check_utf8_support(self) -> bool:
        """检测控制台是否支持UTF-8"""
        try:
            # 尝试写入一个emoji，看是否成功
            test_char = '📋'
            if hasattr(sys.stdout, 'buffer'):
                # 检查是否是UTF-8编码的TextIOWrapper
                if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding:
                    return sys.stdout.encoding.lower() in ('utf-8', 'utf8')
            return False
        except:
            return False

    def _get_safe_icons(self) -> Dict[str, str]:
        """获取安全的图标映射"""
        if self._supports_utf8:
            return NODE_ICONS.copy()
        # ASCII fallback
        return {
            'recon': '[RECON]',
            'analyst': '[ANALYST]',
            'attacker': '[ATTACK]',
            'verifier': '[VERIFY]',
            'explorer': '[EXPLORE]',
            'innovator': '[IDEA]',
            'evolution': '[EVOLVE]',
            'mode_manager': '[MODE]',
            'strategy_filter': '[STRATEGY]',
            'post_exploit': '[POST]',
            'internal_recon': '[INT-RECON]',
            'lateral_move': '[LAT-MOVE]',
            'privilege_escalation': '[PRIVESC]',
            'credential_gather': '[CRED]',
            'default': '[LOG]'
        }

    def format(self, record):
        # 提取节点名（从logger名称）
        parts = record.name.split('.')
        node_name = parts[-1] if parts else 'main'
        icon = self._safe_icons.get(node_name, self._safe_icons['default'])

        # 简洁格式: [图标] 消息
        level_color = COLORS.get(record.levelname, '') if self._supports_utf8 else ''
        msg = record.getMessage()

        # 如果消息已有前缀图标，不再添加
        node_icon_values = list(NODE_ICONS.values())
        if any(icon in msg for icon in node_icon_values):
            reset = COLORS['RESET'] if self._supports_utf8 else ''
            return f"{level_color}{msg}{reset}"

        reset = COLORS['RESET'] if self._supports_utf8 else ''
        return f"{level_color}{icon} {msg}{reset}"


class LoggerManager:
    """日志管理器"""

    _instance: Optional['LoggerManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup()
        return cls._instance

    def _setup(self):
        """初始化日志配置"""
        # 日志根目录 - 使用项目目录下的logs，确保移植性
        project_root = Path(__file__).parent.parent
        self._log_root = Path(os.environ.get('CTF_LOG_DIR', str(project_root / 'logs')))
        self._log_root.mkdir(parents=True, exist_ok=True)

        # 当前任务日志目录
        self._current_task_dir: Optional[Path] = None
        self._task_id: Optional[str] = None

        # 配置根日志器
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.handlers = []

        # 控制台处理器（简洁输出，安全编码处理）
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(ConsoleFormatter())
        # 设置错误处理，避免编码问题导致崩溃
        console_handler.handleError = lambda record: None
        root_logger.addHandler(console_handler)

        self._loggers: Dict[str, logging.Logger] = {}

    def set_task(self, task_id: str):
        """设置当前任务ID，创建任务日志目录"""
        self._task_id = task_id
        self._current_task_dir = self._log_root / task_id
        self._current_task_dir.mkdir(parents=True, exist_ok=True)

        # 清空现有文件处理器，重新创建
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                root_logger.removeHandler(handler)

        # 全流程日志
        all_log = self._current_task_dir / "all.log"
        file_handler = logging.FileHandler(all_log, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(FILE_FORMAT, DATE_FORMAT))
        root_logger.addHandler(file_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """获取日志器"""
        if name not in self._loggers:
            logger = logging.getLogger(name)
            logger.setLevel(logging.DEBUG)
            self._loggers[name] = logger

            # 如果有当前任务，为该logger创建单独文件
            if self._current_task_dir:
                self._add_node_file_handler(logger, name)

        return self._loggers[name]

    def _add_node_file_handler(self, logger: logging.Logger, name: str):
        """为节点添加单独的日志文件"""
        # 提取节点名
        parts = name.split('.')
        node_name = parts[-1] if parts else 'main'

        node_log = self._current_task_dir / f"{node_name}.log"
        handler = logging.FileHandler(node_log, encoding='utf-8')
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(FILE_FORMAT, DATE_FORMAT))
        logger.addHandler(handler)

    def get_task_log_dir(self) -> Optional[Path]:
        """获取当前任务日志目录"""
        return self._current_task_dir

    def get_log_root(self) -> Path:
        """获取日志根目录"""
        return self._log_root


# 全局实例
_logger_manager = LoggerManager()


def get_logger(name: str) -> logging.Logger:
    """获取日志器"""
    return _logger_manager.get_logger(name)


def set_task(task_id: str):
    """设置当前任务"""
    _logger_manager.set_task(task_id)


def get_task_logs(task_id: str) -> Dict:
    """
    获取任务日志信息

    Returns:
        {
            "task_id": str,
            "log_dir": str,
            "logs": {
                "all": {"path": str, "size": int},
                "attacker": {"path": str, "size": int},
                ...
            }
        }
    """
    log_dir = _logger_manager.get_log_root() / task_id
    if not log_dir.exists():
        return {"task_id": task_id, "log_dir": str(log_dir), "logs": {}}

    logs = {}
    for log_file in log_dir.glob("*.log"):
        node_name = log_file.stem
        # 使用文件大小估算行数（避免阻塞读取大文件）
        # 假设每行平均100字节
        estimated_lines = max(1, log_file.stat().st_size // 100)
        logs[node_name] = {
            "path": str(log_file),
            "size": log_file.stat().st_size,
            "lines": estimated_lines,  # 使用估算值避免阻塞
            "lines_estimated": True    # 标记为估算值
        }

    return {
        "task_id": task_id,
        "log_dir": str(log_dir),
        "logs": logs
    }


def list_task_logs() -> list:
    """列出所有任务的日志目录"""
    log_root = _logger_manager.get_log_root()
    tasks = []
    for task_dir in log_root.iterdir():
        if task_dir.is_dir():
            tasks.append({
                "task_id": task_dir.name,
                "log_dir": str(task_dir),
                "created": datetime.fromtimestamp(task_dir.stat().st_mtime).isoformat()
            })
    return sorted(tasks, key=lambda x: x["created"], reverse=True)


# ============================================================================
# 节点日志辅助函数
# ============================================================================

# 消息前缀到节点名的映射
MSG_PREFIX_TO_NODE = {
    "[侦察]": "recon",
    "[分析]": "analyst",
    "[攻击]": "attacker",
    "[核验]": "verifier",
    "[探索]": "explorer",
    "[头脑风暴]": "innovator",
    "[进化]": "evolution",
    "[TypeDetector]": "challenge_type_detector",
    "[模式决策]": "mode_manager",
    "[策略过滤]": "strategy_filter",
    "[后渗透]": "post_exploit",
    "[内网侦察]": "internal_recon",
    "[横向移动]": "lateral_move",
    "[权限提升]": "privilege_escalation",
    "[凭据收集]": "credential_gather",
    "[Log]": "system",
    "[System]": "system",
    "[Signal": "challenge_type_detector",
    "[LLM": "analyst",
    "[Default": "challenge_type_detector",
}


def node_log(node_name: str, message: str, level: str = "info"):
    """
    节点日志快捷函数

    自动从消息中提取节点名（如果消息包含 [侦察]、[攻击] 等标记）

    Args:
        node_name: 节点名 (recon, analyst, attacker等)，若为"main"则自动检测
        message: 日志消息
        level: 日志级别 (debug, info, warning, error)
    """
    # 如果 node_name 是默认值，尝试从消息中提取
    if node_name == "main":
        for prefix, mapped_node in MSG_PREFIX_TO_NODE.items():
            if prefix in message:
                node_name = mapped_node
                break

    logger = get_logger(f"ctf.{node_name}")
    log_func = getattr(logger, level, logger.info)
    log_func(message)


def _safe_emoji(emoji: str, fallback: str = "[OK]") -> str:
    """返回安全的emoji或ASCII替代"""
    # 检测是否支持UTF-8 (延迟检测，避免循环依赖)
    if hasattr(sys.stdout, 'encoding') and sys.stdout.encoding:
        if sys.stdout.encoding.lower() in ('utf-8', 'utf8'):
            return emoji
    return fallback


def log_node_start(node_name: str, **kwargs):
    """记录节点开始执行"""
    icon = _safe_emoji(NODE_ICONS.get(node_name, '📋'), f"[{node_name.upper()}]")
    details = " | ".join(f"{k}={v}" for k, v in kwargs.items() if v)
    msg = f"{icon} [{node_name}] 开始执行"
    if details:
        msg += f" | {details}"
    node_log(node_name, msg, "info")


def log_node_result(node_name: str, success: bool, result: str = ""):
    """记录节点执行结果"""
    icon = _safe_emoji("✅" if success else "❌", "[OK]" if success else "[FAIL]")
    msg = f"{icon} [{node_name}] {'成功' if success else '失败'}"
    if result:
        msg += f": {result[:100]}"
    node_log(node_name, msg, "info" if success else "warning")


def log_attack(action: str, target: str, result: str = ""):
    """记录攻击动作"""
    icon = _safe_emoji("⚔️", "[ATTACK]")
    msg = f"{icon} {action} -> {target}"
    if result:
        msg += f" | {result[:50]}"
    node_log("attacker", msg, "info")


def log_flag_found(flag: str):
    """记录找到FLAG"""
    icon = _safe_emoji("🎉", "[FLAG]")
    node_log("verifier", f"{icon} 找到FLAG: {flag}", "info")


# ============================================================================
# 便捷函数
# ============================================================================

def debug(msg: str):
    get_logger('ctf').debug(msg)

def info(msg: str):
    get_logger('ctf').info(msg)

def warning(msg: str):
    get_logger('ctf').warning(msg)

def error(msg: str):
    get_logger('ctf').error(msg)