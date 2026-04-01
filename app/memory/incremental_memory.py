"""
CTF-Agent 增量记忆系统

借鉴Claude Code的Memory机制:
1. 时间感知 - 记录何时学习、何时过期
2. 主题分类 - 按CTF类别/攻击阶段组织
3. 强度衰减 - 长期未用的记忆自动降级
4. 增量更新 - 只传递新增/变化的知识
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib


class MemoryType(Enum):
    """记忆类型"""
    # 静态知识
    TOOL_KNOWLEDGE = "tool_knowledge"        # 工具使用知识
    VULN_PATTERN = "vuln_pattern"            # 漏洞模式
    TECHNIQUE = "technique"                  # 攻击技术

    # 动态经验
    SUCCESS_CASE = "success_case"            # 成功案例
    FAILURE_LESSON = "failure_lesson"        # 失败教训
    ADAPTATION = "adaptation"                # 环境适应

    # 元知识
    META_STRATEGY = "meta_strategy"          # 元策略（何时用何策略）
    RESOURCE_HINT = "resource_hint"          # 资源提示
    CONSTRAINT = "constraint"                # 约束条件


class MemoryPriority(Enum):
    """记忆优先级"""
    PERMANENT = "permanent"    # 永久记忆（核心知识）
    HIGH = "high"              # 高优先级（近期成功案例）
    MEDIUM = "medium"          # 中等优先级（一般经验）
    LOW = "low"                # 低优先级（陈旧记忆）
    ARCHIVE = "archive"        # 归档（待遗忘）


@dataclass
class MemoryBlock:
    """记忆块"""
    memory_id: str
    memory_type: MemoryType
    priority: MemoryPriority
    topic: str                              # 主题分类
    content: str                            # 记忆内容
    tags: Set[str] = field(default_factory=set)

    # 时间属性
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    access_count: int = 0

    # 关联属性
    related_memories: Set[str] = field(default_factory=set)
    source_agent: str = ""

    # 衰减属性
    initial_strength: float = 1.0
    current_strength: float = 1.0
    decay_rate: float = 0.95                # 每次衰减5%

    # 验证属性
    validated: bool = False
    validation_count: int = 0
    success_rate: float = 0.0

    def access(self):
        """访问记忆（更新访问时间和强度）"""
        self.last_accessed = datetime.now()
        self.access_count += 1
        # 访问增强记忆
        self.current_strength = min(
            self.initial_strength,
            self.current_strength * 1.1
        )

    def decay(self):
        """记忆衰减"""
        self.current_strength *= self.decay_rate

        # 根据强度调整优先级
        if self.current_strength < 0.3:
            self.priority = MemoryPriority.ARCHIVE
        elif self.current_strength < 0.5:
            self.priority = MemoryPriority.LOW
        elif self.current_strength < 0.7:
            self.priority = MemoryPriority.MEDIUM

    def is_expired(self, days: int = 30) -> bool:
        """判断记忆是否过期"""
        if self.priority == MemoryPriority.PERMANENT:
            return False

        age = (datetime.now() - self.last_accessed).days
        return age > days and self.current_strength < 0.3


@dataclass
class MemoryUpdate:
    """记忆更新（增量传输）"""
    update_id: str
    update_type: str                        # add/update/delete
    memory_id: str
    changes: Dict[str, Any]
    timestamp: datetime
    source_session: str


class IncrementalMemorySystem:
    """增量记忆系统"""

    def __init__(self):
        self.memories: Dict[str, MemoryBlock] = {}
        self.updates: List[MemoryUpdate] = []
        self.session_id: str = ""

        # 索引（加速检索）
        self.topic_index: Dict[str, Set[str]] = {}     # topic -> memory_ids
        self.tag_index: Dict[str, Set[str]] = {}       # tag -> memory_ids
        self.type_index: Dict[MemoryType, Set[str]] = {}  # type -> memory_ids

    def add_memory(
        self,
        memory_type: MemoryType,
        topic: str,
        content: str,
        tags: List[str] = None,
        priority: MemoryPriority = MemoryPriority.MEDIUM,
        source_agent: str = ""
    ) -> str:
        """添加记忆"""
        # 生成ID
        content_hash = hashlib.md5(content.encode()).hexdigest()[:8]
        memory_id = f"{memory_type.value}_{topic}_{content_hash}"

        # 检查是否已存在
        if memory_id in self.memories:
            # 已存在则增强
            self.memories[memory_id].access()
            return memory_id

        # 创建新记忆
        memory = MemoryBlock(
            memory_id=memory_id,
            memory_type=memory_type,
            priority=priority,
            topic=topic,
            content=content,
            tags=set(tags or []),
            source_agent=source_agent
        )

        self.memories[memory_id] = memory

        # 更新索引
        self._update_indices_add(memory)

        # 记录更新
        self._record_update("add", memory_id, {"content": content})

        return memory_id

    def update_memory(
        self,
        memory_id: str,
        content: str = None,
        tags: List[str] = None,
        priority: MemoryPriority = None
    ) -> bool:
        """更新记忆"""
        if memory_id not in self.memories:
            return False

        memory = self.memories[memory_id]
        changes = {}

        if content and content != memory.content:
            changes["old_content"] = memory.content
            memory.content = content
            changes["new_content"] = content

        if tags is not None:
            changes["old_tags"] = list(memory.tags)
            memory.tags = set(tags)
            self._update_indices_tags(memory)
            changes["new_tags"] = tags

        if priority and priority != memory.priority:
            changes["old_priority"] = memory.priority.value
            memory.priority = priority
            changes["new_priority"] = priority.value

        if changes:
            memory.access()
            self._record_update("update", memory_id, changes)

        return True

    def delete_memory(self, memory_id: str) -> bool:
        """删除记忆"""
        if memory_id not in self.memories:
            return False

        memory = self.memories[memory_id]

        # 从索引中移除
        self._update_indices_remove(memory)

        # 记录更新
        self._record_update("delete", memory_id, {"reason": "deleted"})

        # 删除记忆
        del self.memories[memory_id]

        return True

    def get_memory(self, memory_id: str) -> Optional[MemoryBlock]:
        """获取记忆"""
        memory = self.memories.get(memory_id)
        if memory:
            memory.access()
        return memory

    def query_by_topic(self, topic: str) -> List[MemoryBlock]:
        """按主题查询"""
        memory_ids = self.topic_index.get(topic, set())
        return [self.memories[mid] for mid in memory_ids if mid in self.memories]

    def query_by_tags(self, tags: List[str]) -> List[MemoryBlock]:
        """按标签查询"""
        result_ids = None

        for tag in tags:
            tag_ids = self.tag_index.get(tag, set())
            if result_ids is None:
                result_ids = tag_ids.copy()
            else:
                result_ids &= tag_ids

        return [
            self.memories[mid]
            for mid in (result_ids or set())
            if mid in self.memories
        ]

    def query_by_type(self, memory_type: MemoryType) -> List[MemoryBlock]:
        """按类型查询"""
        memory_ids = self.type_index.get(memory_type, set())
        return [self.memories[mid] for mid in memory_ids if mid in self.memories]

    def search(self, query: str) -> List[MemoryBlock]:
        """全文搜索"""
        results = []
        query_lower = query.lower()

        for memory in self.memories.values():
            if (
                query_lower in memory.content.lower() or
                query_lower in memory.topic.lower() or
                any(query_lower in tag.lower() for tag in memory.tags)
            ):
                memory.access()
                results.append(memory)

        # 按强度排序
        results.sort(key=lambda m: m.current_strength, reverse=True)
        return results

    def get_recent_memories(
        self,
        hours: int = 24,
        limit: int = 20
    ) -> List[MemoryBlock]:
        """获取最近记忆"""
        cutoff = datetime.now() - timedelta(hours=hours)

        recent = [
            m for m in self.memories.values()
            if m.last_accessed > cutoff
        ]

        recent.sort(key=lambda m: m.last_accessed, reverse=True)
        return recent[:limit]

    def get_high_priority_memories(self) -> List[MemoryBlock]:
        """获取高优先级记忆"""
        return [
            m for m in self.memories.values()
            if m.priority in [MemoryPriority.PERMANENT, MemoryPriority.HIGH]
        ]

    def decay_all(self):
        """衰减所有记忆"""
        for memory in self.memories.values():
            memory.decay()

    def cleanup_expired(self) -> int:
        """清理过期记忆"""
        expired = [
            mid for mid, m in self.memories.items()
            if m.is_expired()
        ]

        for mid in expired:
            self.delete_memory(mid)

        return len(expired)

    def get_incremental_updates(
        self,
        since: datetime = None
    ) -> List[MemoryUpdate]:
        """获取增量更新"""
        if since is None:
            return self.updates

        return [
            u for u in self.updates
            if u.timestamp > since
        ]

    def apply_updates(self, updates: List[MemoryUpdate]):
        """应用增量更新"""
        for update in updates:
            if update.update_type == "add":
                # 从changes重建MemoryBlock
                self.add_memory(
                    memory_type=update.changes.get("type"),
                    topic=update.changes.get("topic"),
                    content=update.changes.get("content"),
                    tags=update.changes.get("tags"),
                    priority=update.changes.get("priority"),
                    source_agent=update.changes.get("source_agent")
                )

            elif update.update_type == "update":
                self.update_memory(
                    memory_id=update.memory_id,
                    content=update.changes.get("new_content"),
                    tags=update.changes.get("new_tags"),
                    priority=update.changes.get("new_priority")
                )

            elif update.update_type == "delete":
                self.delete_memory(update.memory_id)

    def build_prompt_context(
        self,
        max_tokens: int = 5000,
        topics: List[str] = None
    ) -> str:
        """构建Prompt上下文"""
        context_parts = []

        # 1. 高优先级记忆
        high_priority = self.get_high_priority_memories()
        if high_priority:
            context_parts.append("## 核心知识")
            for m in high_priority[:10]:
                context_parts.append(f"- [{m.topic}] {m.content[:200]}")

        # 2. 指定主题记忆
        if topics:
            context_parts.append("\n## 相关经验")
            for topic in topics:
                memories = self.query_by_topic(topic)
                for m in memories[:5]:
                    context_parts.append(
                        f"- {m.memory_type.value}: {m.content[:150]}"
                    )

        # 3. 最近记忆
        recent = self.get_recent_memories(hours=12, limit=5)
        if recent:
            context_parts.append("\n## 最近学习")
            for m in recent:
                context_parts.append(f"- {m.content[:100]}")

        return "\n".join(context_parts)

    def _update_indices_add(self, memory: MemoryBlock):
        """更新索引（添加）"""
        # 主题索引
        if memory.topic not in self.topic_index:
            self.topic_index[memory.topic] = set()
        self.topic_index[memory.topic].add(memory.memory_id)

        # 标签索引
        for tag in memory.tags:
            if tag not in self.tag_index:
                self.tag_index[tag] = set()
            self.tag_index[tag].add(memory.memory_id)

        # 类型索引
        if memory.memory_type not in self.type_index:
            self.type_index[memory.memory_type] = set()
        self.type_index[memory.memory_type].add(memory.memory_id)

    def _update_indices_remove(self, memory: MemoryBlock):
        """更新索引（移除）"""
        # 主题索引
        if memory.topic in self.topic_index:
            self.topic_index[memory.topic].discard(memory.memory_id)

        # 标签索引
        for tag in memory.tags:
            if tag in self.tag_index:
                self.tag_index[tag].discard(memory.memory_id)

        # 类型索引
        if memory.memory_type in self.type_index:
            self.type_index[memory.memory_type].discard(memory.memory_id)

    def _update_indices_tags(self, memory: MemoryBlock):
        """更新标签索引"""
        # 重建标签索引
        for tag in self.tag_index:
            self.tag_index[tag].discard(memory.memory_id)

        for tag in memory.tags:
            if tag not in self.tag_index:
                self.tag_index[tag] = set()
            self.tag_index[tag].add(memory.memory_id)

    def _record_update(
        self,
        update_type: str,
        memory_id: str,
        changes: Dict[str, Any]
    ):
        """记录更新"""
        update = MemoryUpdate(
            update_id=hashlib.md5(
                f"{update_type}_{memory_id}_{datetime.now().isoformat()}".encode()
            ).hexdigest()[:8],
            update_type=update_type,
            memory_id=memory_id,
            changes=changes,
            timestamp=datetime.now(),
            source_session=self.session_id
        )

        self.updates.append(update)

    def export_state(self) -> Dict[str, Any]:
        """导出状态"""
        return {
            "memories": {
                mid: {
                    "memory_id": m.memory_id,
                    "memory_type": m.memory_type.value,
                    "priority": m.priority.value,
                    "topic": m.topic,
                    "content": m.content,
                    "tags": list(m.tags),
                    "created_at": m.created_at.isoformat(),
                    "last_accessed": m.last_accessed.isoformat(),
                    "access_count": m.access_count,
                    "current_strength": m.current_strength,
                    "validated": m.validated,
                    "success_rate": m.success_rate
                }
                for mid, m in self.memories.items()
            },
            "updates_count": len(self.updates),
            "indices": {
                "topics": len(self.topic_index),
                "tags": len(self.tag_index),
                "types": len(self.type_index)
            }
        }

    def get_stats(self) -> Dict[str, Any]:
        """获取统计"""
        priorities = {}
        for m in self.memories.values():
            key = m.priority.value
            priorities[key] = priorities.get(key, 0) + 1

        types = {}
        for m in self.memories.values():
            key = m.memory_type.value
            types[key] = types.get(key, 0) + 1

        avg_strength = (
            sum(m.current_strength for m in self.memories.values()) /
            len(self.memories) if self.memories else 0.0
        )

        return {
            "total_memories": len(self.memories),
            "by_priority": priorities,
            "by_type": types,
            "avg_strength": round(avg_strength, 3),
            "topics_count": len(self.topic_index),
            "tags_count": len(self.tag_index),
            "updates_pending": len(self.updates)
        }


# 全局记忆系统
_memory_system: Optional[IncrementalMemorySystem] = None


def get_memory_system() -> IncrementalMemorySystem:
    """获取全局记忆系统"""
    global _memory_system
    if _memory_system is None:
        _memory_system = IncrementalMemorySystem()
    return _memory_system


# 使用示例
if __name__ == "__main__":
    memory = get_memory_system()

    # 添加记忆
    mid1 = memory.add_memory(
        memory_type=MemoryType.SUCCESS_CASE,
        topic="sqli",
        content="在目标/users?id=1处发现SQL注入，使用UNION注入成功获取flag",
        tags=["sqli", "union", "success"],
        priority=MemoryPriority.HIGH
    )

    mid2 = memory.add_memory(
        memory_type=MemoryType.FAILURE_LESSON,
        topic="xss",
        content="XSS Payload被WAF拦截，需使用编码绕过",
        tags=["xss", "waf", "bypass"],
        priority=MemoryPriority.MEDIUM
    )

    # 查询记忆
    print("SQL注入相关记忆:")
    for m in memory.query_by_topic("sqli"):
        print(f"  - {m.content}")

    # 构建上下文
    print("\nPrompt上下文:")
    print(memory.build_prompt_context(topics=["sqli", "xss"]))

    # 统计
    print("\n" + "=" * 60)
    stats = memory.get_stats()
    print(f"记忆统计: {stats}")