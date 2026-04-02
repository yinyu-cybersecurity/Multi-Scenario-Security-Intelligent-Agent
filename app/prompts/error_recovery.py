# app/prompts/error_recovery.py

"""
错误自纠正提示词 - 参考Claude Code的Self-Correction机制
"""

ERROR_RECOVERY_PROMPT = """
## Error Analysis and Recovery

When a tool fails:
1. Read the error message carefully
2. Identify failure type (parameter, connection, permission, logic)
3. Try alternative approaches
4. Document what didn't work

**Never give up after one failure. Try at least 3 different approaches.**
"""

__all__ = ["ERROR_RECOVERY_PROMPT"]