# app/tools_v2/tool_result.py

"""
统一的工具返回格式

所有工具都应该返回ToolResult实例，确保：
1. AI能够一致地理解工具结果
2. 错误时提供恢复建议
"""

from dataclasses import dataclass
from typing import Any
import json


@dataclass
class ToolResult:
    """统一的工具返回格式"""
    success: bool
    data: Any
    error: str = ""

    def to_message(self) -> str:
        if not self.success:
            return json.dumps({
                "status": "error",
                "error": self.error,
                "suggestion": self._suggest_recovery()
            }, ensure_ascii=False)
        if isinstance(self.data, str):
            return self.data
        return json.dumps({"status": "success", "data": self.data}, ensure_ascii=False)

    def _suggest_recovery(self) -> str:
        err = self.error.lower()
        if "timeout" in err: return "目标可能不可达，检查URL/端口"
        if "not found" in err: return "工具未安装，尝试替代方案"
        if "permission" in err: return "权限不足"
        if "connection refused" in err: return "连接被拒绝，确认端口"
        return "分析错误原因，尝试调整参数"


def normalize_result(result: Any) -> str:
    """统一格式化工具结果为字符串"""
    if isinstance(result, ToolResult):
        return result.to_message()
    if isinstance(result, dict):
        return json.dumps(result, ensure_ascii=False)
    if isinstance(result, str):
        return result
    return str(result)


__all__ = ["ToolResult", "normalize_result"]