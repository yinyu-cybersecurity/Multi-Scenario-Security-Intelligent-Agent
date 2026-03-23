# topology/models.py - 图数据模型定义


from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


class PageNode(BaseModel):
    """页面节点"""
    url: str
    status_code: Optional[int] = None
    fingerprint: Optional[str] = None
    depth: int = 0
    visit_count: int = 0
    
    # [页面变化检测]
    last_file: Optional[str] = None  # 最近一次响应的文件快照路径
    last_md5: Optional[str] = None   # 最近一次响应的内容MD5
    change_count: int = 0            # 该页面内容变化的累计次数
    
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    tags: List[str] = []  # 页面标签（如"login", "admin", "upload"）
    forms: List[Dict] = []
    tech_stack: List[str] = []


class PageEdge(BaseModel):
    """页面间的边（跳转关系）"""
    source: str
    target: str
    edge_type: str  # "link", "form", "redirect", "script"
    weight: float = 1.0
    parameters: Optional[Dict] = None


class AttackPath(BaseModel):
    """攻击路径"""
    nodes: List[str]
    length: int
    score: float  # 路径评分
    critical_nodes: List[str]  # 关键节点