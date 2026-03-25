# logger.py
"""
统一日志配置模块

提供:
- 统一的日志格式
- 分级日志输出
- 文件日志支持
- 性能追踪

使用方式:
    from logger import get_logger
    logger = get_logger(__name__)
    logger.info("信息日志")
    logger.error("错误日志")
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional
from pathlib import Path

# 日志格式
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 颜色代码（终端输出）
COLORS = {
    'DEBUG': '\033[36m',    # 青色
    'INFO': '\033[32m',     # 绿色
    'WARNING': '\033[33m',  # 黄色
    'ERROR': '\033[31m',    # 红色
    'CRITICAL': '\033[35m', # 紫色
    'RESET': '\033[0m'
}


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""

    def format(self, record):
        # 添加颜色
        color = COLORS.get(record.levelname, COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{COLORS['RESET']}"
        return super().format(record)


class LoggerManager:
    """日志管理器"""

    _instance: Optional['LoggerManager'] = None
    _loggers: dict = {}
    _log_dir: Optional[Path] = None
    _console_level: int = logging.INFO
    _file_level: int = logging.DEBUG

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._setup()
        return cls._instance

    def _setup(self):
        """初始化日志配置"""
        # 创建日志目录
        self._log_dir = Path(os.environ.get('CTF_LOG_DIR', '/tmp/ctf_logs'))
        self._log_dir.mkdir(parents=True, exist_ok=True)

        # 配置根日志器
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # 移除现有的处理器
        root_logger.handlers = []

        # 添加控制台处理器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self._console_level)
        console_formatter = ColoredFormatter(LOG_FORMAT, DATE_FORMAT)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # 添加文件处理器
        log_file = self._log_dir / f"ctf_agent_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(self._file_level)
        file_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """获取日志器"""
        if name not in self._loggers:
            self._loggers[name] = logging.getLogger(name)
        return self._loggers[name]

    def set_level(self, level: int):
        """设置日志级别"""
        self._console_level = level
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(level)

    def get_log_file(self) -> str:
        """获取当前日志文件路径"""
        return str(self._log_dir / f"ctf_agent_{datetime.now().strftime('%Y%m%d')}.log")


# 全局日志管理器实例
_logger_manager = LoggerManager()


def get_logger(name: str) -> logging.Logger:
    """
    获取日志器

    Args:
        name: 日志器名称，通常使用 __name__

    Returns:
        logging.Logger: 配置好的日志器

    Example:
        logger = get_logger(__name__)
        logger.info("Starting task")
        logger.error("Task failed", exc_info=True)
    """
    return _logger_manager.get_logger(name)


def set_log_level(level: int):
    """
    设置日志级别

    Args:
        level: logging.DEBUG, INFO, WARNING, ERROR, CRITICAL
    """
    _logger_manager.set_level(level)


def get_log_file() -> str:
    """获取当前日志文件路径"""
    return _logger_manager.get_log_file()


# 便捷函数
def debug(msg: str, *args, **kwargs):
    """调试日志"""
    get_logger('ctf').debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs):
    """信息日志"""
    get_logger('ctf').info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    """警告日志"""
    get_logger('ctf').warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    """错误日志"""
    get_logger('ctf').error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs):
    """严重错误日志"""
    get_logger('ctf').critical(msg, *args, **kwargs)


# 性能追踪装饰器
def log_performance(func):
    """性能追踪装饰器"""
    import time
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.debug(f"[PERF] {func.__name__} completed in {elapsed:.3f}s")
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"[PERF] {func.__name__} failed after {elapsed:.3f}s: {e}")
            raise
    return wrapper