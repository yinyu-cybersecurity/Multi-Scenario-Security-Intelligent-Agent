# app/prompts/__init__.py
"""
CTF提示词模块
"""

from app.prompts.ctf_system_prompt import build_system_prompt

__all__ = ["build_system_prompt"]