# Agent Memory系统
#
# 基于Serena MCP插件实现Agent间通信
# 借鉴Claude Code的Agent间信息传递设计

import json
import os
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import asyncio

# 导入Agent类型
from app.agents.base import AgentType


class MemoryScope(Enum):
    """Memory范围"""
    GLOBAL = "global"      # 全局范围 - 跨项目共享
    PROJECT = "project"    # 项目范围 - 当前项目内共享
    SESSION = "session"    # 会话范围 - 当前会话内有效


@dataclass
class MemoryEntry:
    """Memory条目"""
    name: str
    content: str
    scope: MemoryScope = MemoryScope.PROJECT
    topic: str = ""
    created_by: Optional[AgentType] = None
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    version: int = 1  # 版本号，用于编辑追踪


class AgentMemorySystem:
    """
    Agent间通信系统

    借鉴Claude Code的serena Memory设计，实现:
    1. 结构化知识存储 - 按topic组织
    2. Agent间共享 - 不同Agent可读写共享知识
    3. 命名规范 - 统一的Memory命名体系

    Memory命名规范:
    - explore/{target}/endpoints   - 发现的端点
    - explore/{target}/vulns       - 发现的漏洞
    - explore/{target}/assets      - 内网资产
    - plan/{target}/attack_plan    - 攻击计划
    - attack/{target}/results      - 攻击结果
    - attack/{target}/credentials  - 获取的凭据
    - verify/{target}/flags        - 验证的Flag
    """

    # Memory命名模板
    MEMORY_TEMPLATES = {
        # Explore Agent 写入
        "explore_endpoints": "explore/{target}/endpoints",
        "explore_vulns": "explore/{target}/vulns",
        "explore_assets": "explore/{target}/assets",
        "explore_code_analysis": "explore/{target}/code_analysis",

        # Plan Agent 写入
        "plan_attack": "plan/{target}/attack_plan",
        "plan_vuln_chain": "plan/{target}/vuln_chain",
        "plan_fallback": "plan/{target}/fallback",

        # Attack Agent 写入
        "attack_results": "attack/{target}/results",
        "attack_credentials": "attack/{target}/credentials",
        "attack_flags": "attack/{target}/flags",
        "attack_sessions": "attack/{target}/sessions",

        # Verify Agent 写入
        "verify_flags": "verify/{target}/verified_flags",
        "verify_false_positives": "verify/{target}/false_positives",

        # Global知识
        "global_techniques": "global/techniques/{technique_name}",
        "global_payloads": "global/payloads/{payload_name}",
        "global_tools": "global/tools/{tool_name}",
    }

    def __init__(self, serena_client=None):
        """
        初始化Memory系统

        Args:
            serena_client: Serena MCP客户端实例
        """
        self.serena = serena_client
        self._local_cache: Dict[str, MemoryEntry] = {}

    def _get_memory_name(self, template_key: str, **kwargs) -> str:
        """获取Memory名称"""
        template = self.MEMORY_TEMPLATES.get(template_key)
        if not template:
            raise ValueError(f"Unknown template key: {template_key}")
        return template.format(**kwargs)

    async def write_finding(
        self,
        agent_type: AgentType,
        target: str,
        topic: str,
        data: Dict[str, Any],
        merge: bool = True
    ) -> bool:
        """
        Agent写入发现

        Args:
            agent_type: 写入的Agent类型
            target: 目标标识
            topic: 主题 (endpoints, vulns, etc.)
            data: 发现数据
            merge: 是否与现有数据合并

        Returns:
            是否写入成功
        """
        memory_name = f"{agent_type.value}/{target}/{topic}"

        # 格式化内容
        content = self._format_memory_content(data, agent_type)

        # 如果需要合并，先读取现有数据
        if merge:
            existing = await self._read_internal(memory_name)
            if existing:
                data = self._merge_data(existing, data)
                content = self._format_memory_content(data, agent_type)

        # 写入Memory
        success = await self._write_internal(
            memory_name=memory_name,
            content=content,
            created_by=agent_type
        )

        return success

    async def read_for_agent(
        self,
        agent_type: AgentType,
        topics: List[str],
        target: str = None
    ) -> Dict[str, Any]:
        """
        Agent读取相关记忆

        Args:
            agent_type: 读取的Agent类型
            topics: 主题列表
            target: 目标标识 (可选)

        Returns:
            主题到数据的映射
        """
        memories = {}

        for topic in topics:
            # 构建Memory名称
            if target:
                memory_name = f"{agent_type.value}/{target}/{topic}"
            else:
                memory_name = topic

            try:
                content = await self._read_internal(memory_name)
                if content:
                    memories[topic] = self._parse_memory(content)
            except Exception:
                pass

        return memories

    async def read_cross_agent(
        self,
        topics: List[str],
        target: str = None
    ) -> Dict[str, Any]:
        """
        跨Agent读取记忆

        用于Agent读取其他Agent写入的知识

        Args:
            topics: 完整的Memory名称列表
            target: 目标标识

        Returns:
            主题到数据的映射
        """
        memories = {}

        for topic in topics:
            try:
                content = await self._read_internal(topic)
                if content:
                    memories[topic] = self._parse_memory(content)
            except Exception:
                pass

        return memories

    async def list_available_knowledge(
        self,
        agent_type: AgentType = None,
        target: str = None
    ) -> List[str]:
        """
        列出可用的知识库

        Args:
            agent_type: Agent类型 (可选)
            target: 目标标识 (可选)

        Returns:
            可用Memory名称列表
        """
        if self.serena:
            # 使用Serena列出Memory
            try:
                result = await self.serena.list_memories(
                    topic=f"{agent_type.value}" if agent_type else None
                )
                return [m["name"] for m in result.get("memories", [])]
            except Exception:
                pass

        # 降级到本地缓存
        return list(self._local_cache.keys())

    async def edit_memory(
        self,
        memory_name: str,
        needle: str,
        repl: str,
        mode: str = "literal",
        allow_multiple_occurrences: bool = False
    ) -> bool:
        """
        编辑Memory内容

        Claude Code的edit_memory实现:
        - 支持字面量和正则模式
        - 默认只替换第一个匹配
        - 可选允许多处替换
        - 保持版本追踪

        Args:
            memory_name: Memory名称
            needle: 要查找的内容或正则模式
            repl: 替换内容
            mode: "literal" 或 "regex"
            allow_multiple_occurrences: 是否允许多处替换

        Returns:
            是否编辑成功
        """
        import re

        # 读取现有内容
        content = await self._read_internal(memory_name)
        if not content:
            return False

        # 执行替换
        if mode == "literal":
            if allow_multiple_occurrences:
                new_content = content.replace(needle, repl)
            else:
                # 只替换第一个
                new_content = content.replace(needle, repl, 1)
        else:  # regex模式
            if allow_multiple_occurrences:
                new_content = re.sub(needle, repl, content, flags=re.DOTALL | re.MULTILINE)
            else:
                new_content = re.sub(needle, repl, content, count=1, flags=re.DOTALL | re.MULTILINE)

        # 如果内容有变化，更新
        if new_content != content:
            # 获取现有条目并更新版本
            entry = self._local_cache.get(memory_name)
            if entry:
                entry.version += 1
                entry.content = new_content
                entry.timestamp = time.time()

                # 写入更新
                return await self._write_internal(
                    memory_name=memory_name,
                    content=new_content,
                    created_by=entry.created_by
                )
            else:
                # 创建新条目
                return await self._write_internal(
                    memory_name=memory_name,
                    content=new_content,
                    created_by=None
                )

        return True  # 无变化也算成功

    async def delete_memory(self, memory_name: str) -> bool:
        """
        删除Memory

        Claude Code的delete_memory实现:
        - 从本地缓存删除
        - 从持久化存储删除
        - 返回成功状态

        Args:
            memory_name: Memory名称

        Returns:
            是否删除成功
        """
        # 从本地缓存删除
        if memory_name in self._local_cache:
            del self._local_cache[memory_name]

        # 如果有Serena客户端，也从远程删除
        if self.serena:
            try:
                await self.serena.delete_memory(memory_name=memory_name)
                return True
            except Exception as e:
                print(f"[Memory] Delete failed: {e}")
                return False

        return True

    def _format_memory_content(
        self,
        data: Dict[str, Any],
        agent_type: AgentType
    ) -> str:
        """格式化Memory内容为Markdown"""
        lines = [
            f"# Memory: {agent_type.value}",
            "",
            f"**Created by**: {agent_type.value}",
            f"**Timestamp**: {self._get_timestamp()}",
            "",
            "---",
            "",
        ]

        for key, value in data.items():
            lines.append(f"## {key}")
            lines.append("")
            if isinstance(value, list):
                for item in value:
                    lines.append(f"- {json.dumps(item, ensure_ascii=False)}")
            elif isinstance(value, dict):
                lines.append("```json")
                lines.append(json.dumps(value, indent=2, ensure_ascii=False))
                lines.append("```")
            else:
                lines.append(str(value))
            lines.append("")

        return "\n".join(lines)

    def _parse_memory(self, content: str) -> Dict[str, Any]:
        """解析Memory内容"""
        # 简单解析，提取JSON块
        result = {}

        try:
            # 尝试解析JSON
            if content.startswith("{"):
                return json.loads(content)

            # 解析Markdown格式
            current_key = None
            current_value = []

            for line in content.split("\n"):
                if line.startswith("## "):
                    if current_key:
                        result[current_key] = self._parse_value(current_value)
                    current_key = line[3:].strip()
                    current_value = []
                elif line.startswith("- "):
                    current_value.append(line[2:])
                elif line.startswith("```"):
                    continue
                elif current_key:
                    current_value.append(line)

            if current_key:
                result[current_key] = self._parse_value(current_value)

        except Exception:
            result["raw"] = content

        return result

    def _parse_value(self, lines: List[str]) -> Any:
        """解析值"""
        content = "\n".join(lines).strip()

        # 尝试解析JSON
        try:
            return json.loads(content)
        except Exception:
            pass

        # 返回列表或字符串
        if len(lines) == 1:
            return lines[0]
        return [l for l in lines if l.strip()]

    def _merge_data(self, existing: Dict, new: Dict) -> Dict:
        """合并数据"""
        result = existing.copy()

        for key, value in new.items():
            if key in result:
                if isinstance(result[key], list) and isinstance(value, list):
                    # 列表合并，去重
                    existing_items = {json.dumps(i, sort_keys=True) for i in result[key]}
                    for item in value:
                        if json.dumps(item, sort_keys=True) not in existing_items:
                            result[key].append(item)
                elif isinstance(result[key], dict) and isinstance(value, dict):
                    # 字典合并
                    result[key].update(value)
                else:
                    # 覆盖
                    result[key] = value
            else:
                result[key] = value

        return result

    async def _write_internal(
        self,
        memory_name: str,
        content: str,
        created_by: AgentType
    ) -> bool:
        """内部写入实现"""
        if self.serena:
            try:
                await self.serena.write_memory(
                    memory_name=memory_name,
                    content=content
                )
                return True
            except Exception as e:
                print(f"[Memory] Write failed: {e}")

        # 降级到本地缓存
        self._local_cache[memory_name] = MemoryEntry(
            name=memory_name,
            content=content,
            topic=memory_name.split("/")[0] if "/" in memory_name else "",
            created_by=created_by,
            timestamp=self._get_timestamp()
        )
        return True

    async def _read_internal(self, memory_name: str) -> Optional[str]:
        """内部读取实现"""
        if self.serena:
            try:
                result = await self.serena.read_memory(memory_name=memory_name)
                return result.get("content")
            except Exception:
                pass

        # 降级到本地缓存
        entry = self._local_cache.get(memory_name)
        return entry.content if entry else None

    def _get_timestamp(self) -> float:
        """获取时间戳"""
        import time
        return time.time()


# ============================================
# 便捷函数
# ============================================

_memory_instance: Optional[AgentMemorySystem] = None


def get_memory_system(serena_client=None) -> AgentMemorySystem:
    """获取Memory系统单例"""
    global _memory_instance
    if _memory_instance is None:
        _memory_instance = AgentMemorySystem(serena_client)
    return _memory_instance


async def write_explore_finding(target: str, topic: str, data: Dict) -> bool:
    """便捷函数：Explore Agent写入发现"""
    memory = get_memory_system()
    return await memory.write_finding(AgentType.EXPLORE, target, topic, data)


async def read_attack_plan(target: str) -> Dict:
    """便捷函数：读取攻击计划"""
    memory = get_memory_system()
    return await memory.read_cross_agent([f"plan/{target}/attack_plan"])


async def write_attack_result(target: str, data: Dict) -> bool:
    """便捷函数：Attack Agent写入结果"""
    memory = get_memory_system()
    return await memory.write_finding(AgentType.ATTACK, target, "results", data)


async def write_credential(target: str, credential: Dict) -> bool:
    """便捷函数：写入获取的凭据"""
    memory = get_memory_system()
    return await memory.write_finding(
        AgentType.ATTACK, target, "credentials", credential
    )


async def read_credentials(target: str) -> List[Dict]:
    """便捷函数：读取凭据"""
    memory = get_memory_system()
    data = await memory.read_cross_agent([f"attack/{target}/credentials"])
    return data.get("credentials", [])