# rag_builder/config.py - RAG知识库配置
# 作用：统一管理路径和模型设置

import os
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).parent.parent

# Writeup存放目录
WRITEUPS_DIR = BASE_DIR / "data" / "writeups"

# 向量数据库存储目录
CHROMA_DIR = BASE_DIR / "data" / "chroma_db"

# 自动创建目录
WRITEUPS_DIR.mkdir(parents=True, exist_ok=True)
CHROMA_DIR.mkdir(parents=True, exist_ok=True)

# 支持的WP文件格式
SUPPORTED_EXTENSIONS = [".md", ".txt", ".markdown"]

# Embedding模型配置
import os

# HuggingFace国内镜像
HF_ENDPOINT = os.environ.get('HF_ENDPOINT', 'https://hf-mirror.com')
os.environ['HF_ENDPOINT'] = HF_ENDPOINT

# 多语言模型（~420MB，支持中英文）
EMBEDDING_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

# 性能优化配置
RAG_MAX_MEMORY_MB = 600  # RAG模块最大内存占用（MB）
RAG_MODEL_CACHE_TTL = 3600  # 模型缓存时间（秒），1小时不使用可卸载
RAG_SEARCH_TIMEOUT = 30  # 单次检索超时（秒）
RAG_MAX_CONCURRENT = 2  # 最大并发检索数

# 检索配置
TOP_K_RESULTS = 10  # 默认返回几条相似结果
SIMILARITY_THRESHOLD = 0.3  # 相似度阈值（降低到0.3，让更多结果通过，由AI判断相关性）

# 分块大小（WP内容太长时可以截断）
MAX_CONTENT_LENGTH = 2000  # 只取前2000字符