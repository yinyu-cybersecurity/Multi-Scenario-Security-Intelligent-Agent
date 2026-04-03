# Tool Factory V2 - 工具工厂
#
# 借鉴Claude Code的buildTool设计
# 实现Zod风格参数验证、权限检查、并发安全

from typing import Dict, Any, List, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import json
from datetime import datetime

# 导入权限类型
from app.agents.base import AgentType, ToolPermission


class ParamType(Enum):
    """参数类型"""
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    URI = "uri"
    PATH = "path"


@dataclass
class ParamSchema:
    """参数Schema"""
    name: str
    type: ParamType
    required: bool = True
    description: str = ""
    default: Any = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None  # 正则验证
    enum_values: Optional[List[Any]] = None
    format: Optional[str] = None  # uri, path, email, etc.


@dataclass
class ToolSchema:
    """工具Schema"""
    name: str
    description: str
    parameters: List[ParamSchema]
    returns: ParamType = ParamType.OBJECT
    timeout: int = 60  # 秒
    retry_count: int = 0
    retry_delay: int = 1
    is_read_only: bool = True  # 是否只读（只读工具可并发）
    is_concurrency_safe: bool = True  # 是否并发安全


@dataclass
class ValidationResult:
    """验证结果"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    sanitized_params: Dict[str, Any] = field(default_factory=dict)


class ZodValidator:
    """
    Zod风格参数验证器

    借鉴Claude Code的Zod验证设计:
    - 类型严格检查
    - 范围/长度限制
    - 格式验证（URI、路径）
    - 正则模式匹配
    - 枚举值验证
    """

    def validate(
        self,
        params: Dict[str, Any],
        schema: List[ParamSchema]
    ) -> ValidationResult:
        """
        验证参数

        Args:
            params: 输入参数
            schema: 参数Schema列表

        Returns:
            ValidationResult
        """
        errors = []
        sanitized = {}

        for param_schema in schema:
            param_name = param_schema.name
            param_value = params.get(param_name)

            # 必填检查
            if param_schema.required and param_value is None:
                errors.append(f"{param_name}: Required parameter missing")
                continue

            # 可选参数，未提供时使用默认值
            if param_value is None:
                if param_schema.default is not None:
                    sanitized[param_name] = param_schema.default
                continue

            # 类型检查
            type_error = self._check_type(param_name, param_value, param_schema)
            if type_error:
                errors.append(type_error)
                continue

            # 范围检查
            range_error = self._check_range(param_name, param_value, param_schema)
            if range_error:
                errors.append(range_error)

            # 长度检查
            length_error = self._check_length(param_name, param_value, param_schema)
            if length_error:
                errors.append(length_error)

            # 格式检查
            format_error = self._check_format(param_name, param_value, param_schema)
            if format_error:
                errors.append(format_error)

            # 正则检查
            pattern_error = self._check_pattern(param_name, param_value, param_schema)
            if pattern_error:
                errors.append(pattern_error)

            # 枚举检查
            enum_error = self._check_enum(param_name, param_value, param_schema)
            if enum_error:
                errors.append(enum_error)

            # 安全化处理
            sanitized[param_name] = self._sanitize_value(param_value, param_schema)

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            sanitized_params=sanitized
        )

    def _check_type(
        self,
        name: str,
        value: Any,
        schema: ParamSchema
    ) -> Optional[str]:
        """类型检查"""
        expected_type = schema.type.value

        type_map = {
            ParamType.STRING: str,
            ParamType.INTEGER: int,
            ParamType.NUMBER: (int, float),
            ParamType.BOOLEAN: bool,
            ParamType.ARRAY: list,
            ParamType.OBJECT: dict,
        }

        if schema.type in type_map:
            if not isinstance(value, type_map[schema.type]):
                return f"{name}: Expected {expected_type}, got {type(value).__name__}"

        return None

    def _check_range(
        self,
        name: str,
        value: Any,
        schema: ParamSchema
    ) -> Optional[str]:
        """范围检查"""
        if not isinstance(value, (int, float)):
            return None

        if schema.min_value is not None and value < schema.min_value:
            return f"{name}: Value {value} below minimum {schema.min_value}"

        if schema.max_value is not None and value > schema.max_value:
            return f"{name}: Value {value} above maximum {schema.max_value}"

        return None

    def _check_length(
        self,
        name: str,
        value: Any,
        schema: ParamSchema
    ) -> Optional[str]:
        """长度检查"""
        if not isinstance(value, (str, list)):
            return None

        length = len(value)

        if schema.min_length is not None and length < schema.min_length:
            return f"{name}: Length {length} below minimum {schema.min_length}"

        if schema.max_length is not None and length > schema.max_length:
            return f"{name}: Length {length} above maximum {schema.max_length}"

        return None

    def _check_format(
        self,
        name: str,
        value: Any,
        schema: ParamSchema
    ) -> Optional[str]:
        """格式检查"""
        if schema.format == "uri":
            if not isinstance(value, str):
                return None

            # 简单URI验证
            if not (value.startswith("http://") or value.startswith("https://") or
                    value.startswith("file://") or value.startswith("ftp://")):
                return f"{name}: Invalid URI format"

        elif schema.format == "path":
            if not isinstance(value, str):
                return None

            # 路径安全检查
            dangerous_patterns = ["../", "~/", "..\\"]
            for pattern in dangerous_patterns:
                if pattern in value:
                    return f"{name}: Path traversal detected"

        elif schema.format == "email":
            if not isinstance(value, str):
                return None

            if "@" not in value:
                return f"{name}: Invalid email format"

        return None

    def _check_pattern(
        self,
        name: str,
        value: Any,
        schema: ParamSchema
    ) -> Optional[str]:
        """正则模式检查"""
        if not schema.pattern or not isinstance(value, str):
            return None

        import re
        if not re.match(schema.pattern, value):
            return f"{name}: Does not match pattern {schema.pattern}"

        return None

    def _check_enum(
        self,
        name: str,
        value: Any,
        schema: ParamSchema
    ) -> Optional[str]:
        """枚举值检查"""
        if not schema.enum_values:
            return None

        if value not in schema.enum_values:
            return f"{name}: Invalid value, expected one of {schema.enum_values}"

        return None

    def _sanitize_value(self, value: Any, schema: ParamSchema) -> Any:
        """安全化处理"""
        # 字符串处理
        if isinstance(value, str):
            # 去除危险字符（根据类型）
            if schema.format == "path":
                # 保留合法路径字符
                pass
            elif schema.type == ParamType.STRING:
                # 防止注入
                value = value.strip()

        return value


@dataclass
class ToolExecutionResult:
    """工具执行结果"""
    tool_name: str
    success: bool
    output: Any
    error: Optional[str] = None
    execution_time: float = 0
    retry_count: int = 0
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_dict(self) -> Dict:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "execution_time": self.execution_time,
            "retry_count": self.retry_count,
            "timestamp": self.timestamp
        }


class CTFToolV2:
    """
    CTF工具V2基类

    借鉴Claude Code的工具设计:
    - Schema验证
    - 权限检查
    - 并发安全
    - 超时控制
    """

    def __init__(
        self,
        schema: ToolSchema,
        handler: Callable,
        permissions: List[ToolPermission]
    ):
        self.schema = schema
        self.handler = handler
        self.permissions = permissions
        self.validator = ZodValidator()

        # 并发控制：只读且并发安全的工具不需要semaphore
        # Claude Code模式：细粒度并发控制
        if schema.is_concurrency_safe and schema.is_read_only:
            self._semaphore = None  # 无并发限制
        else:
            self._semaphore = asyncio.Semaphore(1)  # 串行执行

    async def execute(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any],
        agent_type: Optional[AgentType] = None
    ) -> ToolExecutionResult:
        """
        执行工具

        Args:
            params: 工具参数
            context: 执行上下文
            agent_type: 执行的Agent类型

        Returns:
            ToolExecutionResult
        """
        # 1. 参数验证
        validation_result = self.validator.validate(params, self.schema.parameters)

        if not validation_result.valid:
            return ToolExecutionResult(
                tool_name=self.schema.name,
                success=False,
                output=None,
                error=f"Validation failed: {validation_result.errors}"
            )

        # 2. 权限检查
        permission_error = self._check_permissions(agent_type)
        if permission_error:
            return ToolExecutionResult(
                tool_name=self.schema.name,
                success=False,
                output=None,
                error=permission_error
            )

        # 3. 并发控制 - 细粒度
        # Claude Code模式：只读工具可并发，写工具串行
        if self._semaphore:
            async with self._semaphore:
                # 4. 执行（带超时和重试）
                return await self._execute_with_retry(
                    validation_result.sanitized_params,
                    context
                )
        else:
            # 并发安全工具：直接执行
            return await self._execute_with_retry(
                validation_result.sanitized_params,
                context
            )

    def _check_permissions(self, agent_type: Optional[AgentType]) -> Optional[str]:
        """
        权限检查 - 简化版

        遵循Claude Code模式:
        - 如果没有指定agent_type，跳过权限检查（直接调用）
        - 如果指定agent_type，进行基本权限验证
        - 返回简单的错误信息，让AI自己决定如何处理
        """
        # 如果没有指定agent_type，跳过权限检查（用于直接调用）
        if agent_type is None:
            return None

        # 从Agent注册表获取权限
        from app.agents.base import get_agent_definition

        agent_def = get_agent_definition(agent_type)
        if not agent_def:
            return f"Unknown agent: {agent_type.value}"

        # 检查工具是否在禁止列表
        if self.schema.name in agent_def.disallowed_tools:
            return f"Tool '{self.schema.name}' not allowed"

        # 检查工具是否在允许列表
        if self.schema.name not in agent_def.allowed_tools:
            # 通配符检查
            for allowed in agent_def.allowed_tools:
                if allowed.endswith("*"):
                    if self.schema.name.startswith(allowed[:-1]):
                        return None  # 通配符匹配，允许执行
            return f"Tool '{self.schema.name}' not in allowed list"

        return None  # 权限检查通过

    async def _execute_with_retry(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any]
    ) -> ToolExecutionResult:
        """带重试的执行"""
        retry_count = 0
        start_time = datetime.now().timestamp()

        while retry_count <= self.schema.retry_count:
            try:
                # 执行（带超时）
                result = await asyncio.wait_for(
                    self._call_handler(params, context),
                    timeout=self.schema.timeout
                )

                execution_time = datetime.now().timestamp() - start_time

                return ToolExecutionResult(
                    tool_name=self.schema.name,
                    success=True,
                    output=result,
                    execution_time=execution_time,
                    retry_count=retry_count
                )

            except asyncio.TimeoutError:
                retry_count += 1
                if retry_count <= self.schema.retry_count:
                    await asyncio.sleep(self.schema.retry_delay)
                else:
                    return ToolExecutionResult(
                        tool_name=self.schema.name,
                        success=False,
                        output=None,
                        error="Execution timeout",
                        execution_time=self.schema.timeout,
                        retry_count=retry_count
                    )

            except Exception as e:
                retry_count += 1
                if retry_count <= self.schema.retry_count:
                    await asyncio.sleep(self.schema.retry_delay)
                else:
                    execution_time = datetime.now().timestamp() - start_time
                    return ToolExecutionResult(
                        tool_name=self.schema.name,
                        success=False,
                        output=None,
                        error=str(e),
                        execution_time=execution_time,
                        retry_count=retry_count
                    )

    async def _call_handler(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Any:
        """调用Handler"""
        if asyncio.iscoroutinefunction(self.handler):
            return await self.handler(params, context)
        else:
            return self.handler(params, context)

    def get_schema_dict(self) -> Dict:
        """获取Schema字典（用于API格式）"""
        properties = {}
        required = []

        for param in self.schema.parameters:
            properties[param.name] = {
                "type": param.type.value,
                "description": param.description,
            }

            if param.min_value is not None:
                properties[param.name]["minimum"] = param.min_value
            if param.max_value is not None:
                properties[param.name]["maximum"] = param.max_value
            if param.min_length is not None:
                properties[param.name]["minLength"] = param.min_length
            if param.max_length is not None:
                properties[param.name]["maxLength"] = param.max_length
            if param.enum_values is not None:
                properties[param.name]["enum"] = param.enum_values
            if param.format is not None:
                properties[param.name]["format"] = param.format
            if param.default is not None:
                properties[param.name]["default"] = param.default

            if param.required:
                required.append(param.name)

        return {
            "name": self.schema.name,
            "description": self.schema.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }


# ============================================
# buildTool 工厂函数
# ============================================

def buildTool(
    name: str,
    description: str,
    parameters: List[Dict[str, Any]],
    handler: Callable,
    permissions: List[ToolPermission],
    timeout: int = 60,
    retry_count: int = 0,
    retry_delay: int = 1,
    is_read_only: bool = True,
    is_concurrency_safe: bool = True
) -> CTFToolV2:
    """
    工具工厂函数

    借鉴Claude Code的buildTool设计:
    - 声明式参数定义
    - Zod风格验证
    - 权限绑定
    - 细粒度并发控制

    示例:
        sqlmap_tool = buildTool(
            name="sqlmap",
            description="SQL注入自动化利用",
            parameters=[
                {"name": "target_url", "type": "uri", "required": True},
                {"name": "level", "type": "integer", "min": 1, "max": 5}
            ],
            handler=sqlmap_handler,
            permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
            is_read_only=False,  # 写操作
            is_concurrency_safe=False  # 需要串行
        )

    Args:
        name: 工具名称
        description: 工具描述
        parameters: 参数定义列表（字典格式）
        handler: 执行Handler
        permissions: 所需权限
        timeout: 超时时间（秒）
        retry_count: 重试次数
        retry_delay: 重试延迟（秒）
        is_read_only: 是否只读（只读工具可并发）
        is_concurrency_safe: 是否并发安全

    Returns:
        CTFToolV2实例
    """
    # 转换参数字典到ParamSchema
    param_schemas = []
    for param_dict in parameters:
        param_type = ParamType(param_dict.get("type", "string"))

        param_schema = ParamSchema(
            name=param_dict["name"],
            type=param_type,
            required=param_dict.get("required", True),
            description=param_dict.get("description", ""),
            default=param_dict.get("default"),
            min_value=param_dict.get("min"),
            max_value=param_dict.get("max"),
            min_length=param_dict.get("min_length"),
            max_length=param_dict.get("max_length"),
            pattern=param_dict.get("pattern"),
            enum_values=param_dict.get("enum"),
            format=param_dict.get("format")
        )

        param_schemas.append(param_schema)

    # 构建工具Schema
    tool_schema = ToolSchema(
        name=name,
        description=description,
        parameters=param_schemas,
        timeout=timeout,
        retry_count=retry_count,
        retry_delay=retry_delay,
        is_read_only=is_read_only,
        is_concurrency_safe=is_concurrency_safe
    )

    return CTFToolV2(
        schema=tool_schema,
        handler=handler,
        permissions=permissions
    )


def ensure_result_format(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    确保结果格式规范

    用于Handler返回结果的标准格式化

    Args:
        result: 原始结果

    Returns:
        标准格式结果
    """
    return {
        "success": result.get("success", False),
        "data": result.get("data"),
        "error": result.get("error"),
        "metadata": result.get("metadata", {}),
        "timestamp": datetime.now().timestamp()
    }


# ============================================
# 工具注册表
# ============================================

class ToolRegistryV2:
    """
    工具注册表V2

    管理所有注册的工具
    """

    def __init__(self):
        self._tools: Dict[str, CTFToolV2] = {}

    def register(self, tool: CTFToolV2):
        """注册工具"""
        self._tools[tool.schema.name] = tool

    def get_tool(self, name: str) -> Optional[CTFToolV2]:
        """获取工具"""
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        """列出所有工具"""
        return list(self._tools.keys())

    def get_tools_for_agent(self, agent_type: AgentType) -> List[CTFToolV2]:
        """获取Agent可用的工具"""
        from app.agents.base import get_agent_definition

        agent_def = get_agent_definition(agent_type)
        if not agent_def:
            return []

        available_tools = []
        for tool in self._tools.values():
            # 检查权限
            perm_error = tool._check_permissions(agent_type)
            if not perm_error:
                available_tools.append(tool)

        return available_tools

    def get_all_schemas(self) -> List[Dict]:
        """获取所有工具Schema"""
        return [tool.get_schema_dict() for tool in self._tools.values()]


_registry_v2: Optional[ToolRegistryV2] = None


def get_tool_registry_v2() -> ToolRegistryV2:
    """获取工具注册表单例"""
    global _registry_v2
    if _registry_v2 is None:
        _registry_v2 = ToolRegistryV2()
    return _registry_v2


def register_tool(tool: CTFToolV2):
    """便捷函数：注册工具"""
    registry = get_tool_registry_v2()
    registry.register(tool)