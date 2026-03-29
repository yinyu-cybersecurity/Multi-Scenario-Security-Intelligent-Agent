# app/prompts/__init__.py
"""
Prompt 注册中心

统一管理所有场景的 Prompt，提供查询和获取接口。

使用方式:
    from prompts import PromptRegistry, get_prompt

    # 获取 prompt
    prompt = get_prompt('analyst', 'web')
    prompt = get_prompt('internal_recon')

    # 列出所有 prompt
    PromptRegistry.list_prompts()

    # 使用共享场景框架
    from prompts.scene_framework import (
        get_scene_framework_for_attacker,
        get_scene_framework_for_analyst,
        get_encoding_tips,
        get_new_path_discovery_tips,
        get_success_criteria,
        get_tool_selection_principles,
        get_attack_decision_principles,
        SCENE_TOOL_MAPPING
    )
"""

from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field

# 导出场景框架模块
from .scene_framework import (
    SCENE_FRAMEWORK,
    SCENE_RECOGNITION_DETAIL,
    SCENE_STRATEGY_MAPPING,
    SCENE_TOOL_MAPPING,
    ENCODING_TIPS,
    NEW_PATH_DISCOVERY_TIPS,
    SUCCESS_CRITERIA,
    TOOL_SELECTION_PRINCIPLES,
    ATTACK_DECISION_PRINCIPLES,
    get_scene_framework_for_attacker,
    get_scene_framework_for_analyst,
    get_encoding_tips,
    get_new_path_discovery_tips,
    get_success_criteria,
    get_tool_selection_principles,
    get_attack_decision_principles,
    get_recommended_tools,
)


@dataclass
class PromptInfo:
    """Prompt 信息"""
    name: str
    category: str
    description: str
    get_func: Callable
    aliases: List[str] = field(default_factory=list)


class PromptRegistry:
    """
    Prompt 注册中心

    管理 CTF-Agent 中所有场景的 Prompt
    """

    _prompts: Dict[str, PromptInfo] = {}

    @classmethod
    def register(cls, name: str, category: str, description: str,
                 get_func: Callable, aliases: List[str] = None):
        """
        注册 Prompt

        Args:
            name: Prompt 名称
            category: 分类 (web, internal, crypto, pwn, reverse, misc)
            description: 描述
            get_func: 获取 prompt 的函数
            aliases: 别名列表
        """
        info = PromptInfo(
            name=name,
            category=category,
            description=description,
            get_func=get_func,
            aliases=aliases or []
        )
        cls._prompts[name] = info
        for alias in (aliases or []):
            cls._prompts[alias] = info

    @classmethod
    def get(cls, name: str, default: str = None, **kwargs) -> str:
        """
        获取 Prompt 内容

        Args:
            name: Prompt 名称或别名
            default: 获取失败时的默认返回值
            **kwargs: 传递给 get_func 的参数

        Returns:
            Prompt 字符串，如果获取失败且提供了 default 则返回 default
        """
        if name not in cls._prompts:
            if default is not None:
                return default
            raise KeyError(f"Prompt not found: {name}")

        try:
            return cls._prompts[name].get_func(**kwargs)
        except TypeError:
            # 如果参数不匹配，尝试无参数调用
            try:
                return cls._prompts[name].get_func()
            except Exception:
                if default is not None:
                    return default
                raise

    @classmethod
    def exists(cls, name: str) -> bool:
        """检查 Prompt 是否存在"""
        return name in cls._prompts

    @classmethod
    def list_prompts(cls, category: str = None) -> List[str]:
        """
        列出所有注册的 Prompt

        Args:
            category: 可选的分类过滤
        """
        seen_names = set()
        result = []
        for name, info in cls._prompts.items():
            if name == info.name:  # 只返回主名称，不返回别名
                if category is None or info.category == category:
                    result.append(name)
        return result

    @classmethod
    def get_categories(cls) -> List[str]:
        """获取所有分类"""
        categories = set()
        for info in cls._prompts.values():
            categories.add(info.category)
        return list(categories)

    @classmethod
    def get_info(cls, name: str) -> Optional[PromptInfo]:
        """获取 Prompt 信息"""
        return cls._prompts.get(name)


def get_prompt(name: str, **kwargs) -> str:
    """便捷函数：获取 Prompt"""
    return PromptRegistry.get(name, **kwargs)


# ============================================================================
# 自动注册所有 Prompt
# ============================================================================

def _auto_register():
    """自动注册所有 Prompt"""

    # Web CTF Prompts
    try:
        from analyst_prompt import get_analyst_prompt
        # 使用 lambda 包装，提供默认参数支持
        PromptRegistry.register(
            name='analyst',
            category='web',
            description='分析兵 Prompt - 漏洞识别和分析',
            get_func=lambda page_features=None, raw_html='', rule_candidates=None, **kw:
                get_analyst_prompt(
                    page_features or {},
                    raw_html,
                    rule_candidates or [],
                    **{k: v for k, v in kw.items() if k in ['task_name', 'task_description', 'baseline_response', 'detected_scenes', 'tools_info', 'focused_scene', 'scene_tested']}
                ),
            aliases=['web_analyst']
        )
    except ImportError:
        pass

    try:
        from attacker_prompt import get_attacker_prompt
        # 使用 lambda 包装
        PromptRegistry.register(
            name='attacker',
            category='web',
            description='攻击兵 Prompt - 漏洞利用',
            get_func=lambda vuln_candidates=None, tool_definitions='', **kw:
                get_attacker_prompt(
                    vuln_candidates or [],
                    tool_definitions,
                    **{k: v for k, v in kw.items() if k in ['attack_history', 'task_info', 'tactical_guidance', 'analyst_intel', 'known_facts']}
                ),
            aliases=['web_attacker']
        )
    except ImportError:
        pass

    try:
        from verifier_prompt import get_verifier_prompt
        PromptRegistry.register(
            name='verifier',
            category='web',
            description='核验兵 Prompt - 结果验证',
            get_func=lambda attack_batch=None, results=None, **kw:
                get_verifier_prompt(
                    attack_batch or [],
                    results or [],
                    **{k: v for k, v in kw.items() if k in ['analyst_intel', 'node_info', 'known_facts', 'human_hint']}
                ),
            aliases=['web_verifier']
        )
    except ImportError:
        pass

    # Internal Network Prompts
    try:
        from internal_network.prompts import (
            get_internal_recon_prompt,
            get_lateral_move_prompt,
            get_privilege_escalation_prompt
        )
        PromptRegistry.register(
            name='internal_recon',
            category='internal',
            description='内网侦察 Prompt',
            get_func=lambda **kw: get_internal_recon_prompt(**kw) if 'target' in kw else get_internal_recon_prompt.__code__.co_consts[1]
        )
        PromptRegistry.register(
            name='lateral_move',
            category='internal',
            description='横向移动 Prompt',
            get_func=lambda **kw: get_lateral_move_prompt(**kw) if 'target' in kw else get_lateral_move_prompt.__code__.co_consts[1]
        )
        PromptRegistry.register(
            name='privilege_escalation',
            category='internal',
            description='权限提升 Prompt',
            get_func=lambda **kw: get_privilege_escalation_prompt(**kw) if 'target' in kw else get_privilege_escalation_prompt.__code__.co_consts[1]
        )
    except ImportError:
        pass

    # Crypto Prompts
    try:
        from crypto.prompts import (
            get_crypto_analysis_prompt,
            get_rsa_analysis_prompt,
            get_classical_cipher_prompt,
            get_encoding_detection_prompt,
        )
        PromptRegistry.register(
            name='crypto_analysis',
            category='crypto',
            description='密码分析 Prompt',
            get_func=get_crypto_analysis_prompt
        )
        PromptRegistry.register(
            name='rsa_analysis',
            category='crypto',
            description='RSA 分析 Prompt',
            get_func=get_rsa_analysis_prompt
        )
        PromptRegistry.register(
            name='classical_cipher',
            category='crypto',
            description='古典密码 Prompt',
            get_func=get_classical_cipher_prompt
        )
        PromptRegistry.register(
            name='encoding_detection',
            category='crypto',
            description='编码检测 Prompt',
            get_func=get_encoding_detection_prompt
        )
    except ImportError:
        pass

    # Pwn Prompts
    try:
        from pwn.prompts import (
            get_pwn_analysis_prompt,
            get_buffer_overflow_prompt,
            get_rop_chain_prompt,
            get_format_string_prompt,
        )
        PromptRegistry.register(
            name='pwn_analysis',
            category='pwn',
            description='Pwn 分析 Prompt',
            get_func=get_pwn_analysis_prompt
        )
        PromptRegistry.register(
            name='buffer_overflow',
            category='pwn',
            description='缓冲区溢出 Prompt',
            get_func=get_buffer_overflow_prompt
        )
        PromptRegistry.register(
            name='rop_chain',
            category='pwn',
            description='ROP 链构造 Prompt',
            get_func=get_rop_chain_prompt
        )
        PromptRegistry.register(
            name='format_string',
            category='pwn',
            description='格式化字符串 Prompt',
            get_func=get_format_string_prompt
        )
    except ImportError:
        pass

    # Reverse Prompts
    try:
        from reverse.prompts import (
            get_reverse_analysis_prompt,
            get_algorithm_identification_prompt,
            get_flag_extraction_prompt,
        )
        PromptRegistry.register(
            name='reverse_analysis',
            category='reverse',
            description='逆向分析 Prompt',
            get_func=get_reverse_analysis_prompt
        )
        PromptRegistry.register(
            name='algorithm_identification',
            category='reverse',
            description='算法识别 Prompt',
            get_func=get_algorithm_identification_prompt
        )
        PromptRegistry.register(
            name='flag_extraction',
            category='reverse',
            description='Flag 提取 Prompt',
            get_func=get_flag_extraction_prompt
        )
    except ImportError:
        pass

    # Misc Prompts
    try:
        from misc.prompts import (
            get_misc_analysis_prompt,
            get_steganography_prompt,
            get_forensics_prompt,
        )
        PromptRegistry.register(
            name='misc_analysis',
            category='misc',
            description='Misc 分析 Prompt',
            get_func=get_misc_analysis_prompt
        )
        PromptRegistry.register(
            name='steganography',
            category='misc',
            description='隐写术 Prompt',
            get_func=get_steganography_prompt
        )
        PromptRegistry.register(
            name='forensics',
            category='misc',
            description='取证分析 Prompt',
            get_func=get_forensics_prompt
        )
    except ImportError:
        pass


# 执行自动注册
_auto_register()