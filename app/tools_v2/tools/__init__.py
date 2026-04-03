"""
CTF安全工具 - 简化版

设计原则：
1. 工具Schema仅包含元数据（名称、描述、分类、示例）
2. 工具路径由tool_paths.py管理
3. 工具执行由native_executor处理
4. AI通过skill文档了解工具用法，直接调用Bash执行
"""

from .simple_tools import (
    TOOL_SCHEMAS,
    HANDLERS,
    get_tool_schema,
    list_tools,
    get_all_schemas,
    validate_target,
    validate_url_for_ssrf,
    validate_ports,
)

__all__ = [
    # Schema
    "TOOL_SCHEMAS",
    "HANDLERS",

    # API
    "get_tool_schema",
    "list_tools",
    "get_all_schemas",

    # 安全验证
    "validate_target",
    "validate_url_for_ssrf",
    "validate_ports",
]


def register_tools(registry):
    """
    注册工具到Registry

    修复：工具需要实际执行，而不是返回"metadata only"
    使用native_executor执行命令
    """
    from app.tools_v2.tool_factory import buildTool, get_tool_registry_v2, ParamType
    from app.agents.base import ToolPermission
    from app.tools_v2.native_executor import get_native_executor
    import logging

    logger = logging.getLogger(__name__)

    # 如果传入None，使用全局registry
    if registry is None:
        registry = get_tool_registry_v2()

    # 特殊工具：load_skill
    async def load_skill_handler(params, context):
        """加载Skill内容"""
        skill_name = params.get("name", "")

        if not skill_name:
            return {
                "success": False,
                "error": "Skill name required",
                "hint": "Example: load_skill meta_skill_selector"
            }

        try:
            from app.skills import get_skill_registry

            skill_registry = get_skill_registry()
            skill = skill_registry.get_skill(skill_name)

            if not skill:
                # 列出可用Skills
                available = skill_registry.list_skills()
                return {
                    "success": False,
                    "error": f"Skill '{skill_name}' not found",
                    "available_skills": available[:20],  # 只显示前20个
                    "hint": "Use load_skill meta_skill_selector first to see scenario→Skill mapping"
                }

            # 返回完整Skill内容
            return {
                "success": True,
                "skill_id": skill.skill_id,  # 唯一标识（文件名）
                "skill_name": skill.name,    # 显示名称（可以是中文）
                "description": skill.description,
                "domain": skill.domain,
                "knowledge": skill.knowledge,
                "tool_preferences": [
                    {"tool": p.tool_name, "score": p.score, "reason": p.reason}
                    for p in skill.tool_preferences
                ] if skill.tool_preferences else [],
                "workflows": [
                    {
                        "name": w.name,
                        "steps": [{"description": s.description, "suggested_tools": s.suggested_tools}
                                  for s in w.steps]
                    }
                    for w in skill.workflows
                ] if skill.workflows else [],
                "examples": [
                    {"scenario": e.scenario, "solution": e.solution, "tools": e.tools_used}
                    for e in skill.examples
                ] if skill.examples else []
            }

        except Exception as e:
            logger.error(f"Load skill error: {e}")
            return {"success": False, "error": str(e)}

    # 注册 load_skill 工具
    load_skill_tool = buildTool(
        name="load_skill",
        description="加载指定名称的Skill，获取领域知识和工具推荐",
        parameters=[
            {
                "name": "name",
                "type": "string",
                "required": True,
                "description": "Skill名称，如 meta_skill_selector, rce_attack-chain, sqli_union"
            }
        ],
        handler=load_skill_handler,
        permissions=[],
        timeout=10,
    )
    registry.register(load_skill_tool)

    # 特殊工具：dispatch_agent
    async def dispatch_agent_handler(params, context):
        """派发子Agent并行执行"""
        import asyncio
        import json

        targets_raw = params.get("targets", "[]")
        task = params.get("task", "")

        if not task:
            return {
                "success": False,
                "error": "Task description required",
                "hint": "Example: dispatch_agent targets=['192.168.1.10','192.168.1.20'] task='扫描目标'"
            }

        # 解析 targets（可能是 JSON 字符串或列表）
        if isinstance(targets_raw, str):
            try:
                targets = json.loads(targets_raw)
            except json.JSONDecodeError:
                # 尝试逗号分隔
                targets = [t.strip() for t in targets_raw.split(',') if t.strip()]
        else:
            targets = targets_raw

        if not targets:
            return {
                "success": False,
                "error": "Targets list required",
                "hint": "Example: targets=['192.168.1.10','192.168.1.20']"
            }

        try:
            from app.memory.prompt_cache import get_fork_manager

            fork_manager = get_fork_manager()

            # 获取父 Agent 的消息（从 context）
            parent_messages = context.get("messages", [])
            if not parent_messages:
                # 创建简单的初始消息
                parent_messages = [{
                    "role": "user",
                    "content": [{"type": "text", "text": context.get("original_task", "")}]
                }]

            # 创建并行 Fork 任务
            fork_tasks = fork_manager.create_parallel_forks(
                targets=targets,
                task_template=task,
                parent_messages=parent_messages,
                agent_type="explore"
            )

            logger.info(f"[dispatch_agent] Created {len(fork_tasks)} parallel tasks")

            return {
                "success": True,
                "message": f"已派发 {len(targets)} 个并行任务",
                "targets": targets,
                "task": task,
                "fork_tasks": [
                    {
                        "target": t.get("target"),
                        "status": "pending"
                    }
                    for t in fork_tasks
                ],
                "hint": "子Agent正在并行执行，结果将通过事件流返回"
            }

        except Exception as e:
            logger.error(f"Dispatch agent error: {e}")
            return {"success": False, "error": str(e)}

    # 注册 dispatch_agent 工具
    dispatch_agent_tool = buildTool(
        name="dispatch_agent",
        description="派发子Agent并行执行独立任务",
        parameters=[
            {
                "name": "targets",
                "type": "array",
                "required": True,
                "description": "目标列表，如 ['192.168.1.10','192.168.1.20']"
            },
            {
                "name": "task",
                "type": "string",
                "required": True,
                "description": "任务描述，每个目标执行的任务"
            }
        ],
        handler=dispatch_agent_handler,
        permissions=[],
        timeout=10,
    )
    registry.register(dispatch_agent_tool)

    # 特殊工具：write_memory
    async def write_memory_handler(params, context):
        """写入Memory"""
        topic = params.get("topic", "")
        content = params.get("content", "")

        if not topic or not content:
            return {
                "success": False,
                "error": "Both topic and content required"
            }

        try:
            from app.memory import get_agent_memory

            memory = get_agent_memory()
            target = context.get("target", "unknown")

            memory.write_finding(
                agent_type="coordinator",
                target=target,
                topic=topic,
                finding=content
            )

            return {
                "success": True,
                "message": f"已记录到Memory: {topic}",
                "topic": topic
            }

        except Exception as e:
            logger.error(f"Write memory error: {e}")
            return {"success": False, "error": str(e)}

    # 注册 write_memory 工具
    write_memory_tool = buildTool(
        name="write_memory",
        description="将发现写入Memory供后续查询",
        parameters=[
            {
                "name": "topic",
                "type": "string",
                "required": True,
                "description": "主题，如 sql_injection, credentials, vulnerability"
            },
            {
                "name": "content",
                "type": "string",
                "required": True,
                "description": "发现内容"
            }
        ],
        handler=write_memory_handler,
        permissions=[],
        timeout=5,
    )
    registry.register(write_memory_tool)

    # 特殊工具：read_memory
    async def read_memory_handler(params, context):
        """读取Memory"""
        topic = params.get("topic", "")
        topics_raw = params.get("topics", "[]")

        try:
            from app.memory import get_agent_memory

            memory = get_agent_memory()
            target = context.get("target", "unknown")

            # 解析 topics
            if isinstance(topics_raw, str):
                import json
                try:
                    topics = json.loads(topics_raw)
                except:
                    topics = [topic] if topic else []
            else:
                topics = topics_raw

            if not topics and topic:
                topics = [topic]

            findings = []
            for t in topics:
                results = memory.read_findings(
                    agent_type="coordinator",
                    target=target,
                    topic=t
                )
                if results:
                    findings.extend(results)

            return {
                "success": True,
                "findings": findings,
                "topics_queried": topics
            }

        except Exception as e:
            logger.error(f"Read memory error: {e}")
            return {"success": False, "error": str(e)}

    # 注册 read_memory 工具
    read_memory_tool = buildTool(
        name="read_memory",
        description="从Memory读取历史发现",
        parameters=[
            {
                "name": "topic",
                "type": "string",
                "required": False,
                "description": "主题"
            },
            {
                "name": "topics",
                "type": "array",
                "required": False,
                "description": "主题列表"
            }
        ],
        handler=read_memory_handler,
        permissions=[],
        timeout=5,
    )
    registry.register(read_memory_tool)

    # 创建执行handler工厂函数 - 闭包捕获tool_name
    def make_execute_handler(tool_name: str):
        """创建工具执行handler（闭包捕获tool_name）"""
        async def execute_handler(params, context):
            """真正执行工具命令"""
            args_str = params.get("args", "")
            timeout = params.get("timeout", 120)

            if not args_str:
                return {
                    "success": False,
                    "error": "No arguments provided",
                    "hint": f"Example usage: {tool_name} -u http://target.com"
                }

            # 解析参数（保持引号内的内容完整）
            import shlex
            try:
                args_list = shlex.split(args_str)
            except ValueError as e:
                return {"success": False, "error": f"Invalid arguments: {e}"}

            try:
                executor = get_native_executor()

                # 检查工具可用性
                availability = await executor.check_available(tool_name)
                if not availability.get("is_available"):
                    install_hint = get_install_hint(tool_name)
                    return {
                        "success": False,
                        "error": f"Tool '{tool_name}' not available: {availability.get('error', 'not found')}",
                        "hint": install_hint
                    }

                # 执行工具
                logger.info(f"Executing {tool_name} with args: {args_str[:100]}...")
                result = await executor.execute(
                    tool_name=tool_name,
                    args=args_list,
                    timeout=timeout * 1000  # 转换为毫秒
                )

                logger.info(f"{tool_name} result: success={result.get('success')}")
                return result

            except Exception as e:
                logger.error(f"Tool execution error for {tool_name}: {e}")
                return {"success": False, "error": str(e)}

        return execute_handler

    def get_install_hint(tool_name: str) -> str:
        """获取安装提示"""
        hints = {
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
            "sqlmap": "pip install sqlmap",
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "gobuster": "go install github.com/OJ/gobuster/v3@latest",
        }
        return hints.get(tool_name, f"Install {tool_name} using package manager")

    for name, schema in TOOL_SCHEMAS.items():
        # 跳过特殊工具（已单独注册）
        if name in ["load_skill", "dispatch_agent", "write_memory", "read_memory"]:
            continue

        # 为每个工具创建专用handler
        handler = make_execute_handler(name)

        # 使用buildTool创建工具对象
        tool = buildTool(
            name=name,
            description=schema.get("description", ""),
            parameters=[
                {
                    "name": "args",
                    "type": "string",
                    "required": True,
                    "description": f"命令参数，示例: {', '.join(schema.get('examples', []))}"
                },
                {
                    "name": "timeout",
                    "type": "integer",
                    "required": False,
                    "description": "超时时间（秒）",
                    "default": 120
                }
            ],
            handler=handler,
            permissions=[],
            timeout=180,  # 默认3分钟超时
        )
        registry.register(tool)