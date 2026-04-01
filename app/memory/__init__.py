# Memory系统
#
# Agent间通信基础设施
#
# Claude Code借鉴:
# 1. Prompt Cache - 共享上下文池，90% Token节省
# 2. Context Compressor - 增量更新，只传输变化部分
# 3. Error Recovery - 自主恢复策略，指数退避
# 4. Incremental Memory - 知识积累与遗忘，强度衰减

from .agent_memory import (
    AgentMemorySystem,
    MemoryEntry,
    get_memory_system as get_agent_memory,
    write_explore_finding,
    read_attack_plan,
    write_attack_result,
    write_credential,
    read_credentials,
)

from .prompt_cache import (
    PromptCacheManager,
    ForkSubagentManager,
    Message,
    ToolUseBlock,
    ToolResultBlock,
    FORK_PLACEHOLDER_RESULT,
    get_cache_manager,
    get_fork_manager,
    fork_parallel_scan,
)

from .context_compressor import (
    ContextCompressor,
    ContextBlock,
    SharedContext,
    get_context_compressor
)

from .error_recovery import (
    ErrorRecoveryEngine,
    ErrorRecord,
    ErrorType,
    ErrorSeverity,
    RecoveryStrategy,
    get_error_recovery
)

from .incremental_memory import (
    IncrementalMemorySystem,
    MemoryBlock,
    MemoryUpdate,
    MemoryType,
    MemoryPriority,
    get_memory_system
)

__all__ = [
    # Agent Memory
    "AgentMemorySystem",
    "MemoryEntry",
    "get_agent_memory",
    "write_explore_finding",
    "read_attack_plan",
    "write_attack_result",
    "write_credential",
    "read_credentials",

    # Prompt Cache
    "PromptCacheManager",
    "ForkSubagentManager",
    "Message",
    "ToolUseBlock",
    "ToolResultBlock",
    "FORK_PLACEHOLDER_RESULT",
    "get_cache_manager",
    "get_fork_manager",
    "fork_parallel_scan",

    # Context Compressor
    "ContextCompressor",
    "ContextBlock",
    "SharedContext",
    "get_context_compressor",

    # Error Recovery
    "ErrorRecoveryEngine",
    "ErrorRecord",
    "ErrorType",
    "ErrorSeverity",
    "RecoveryStrategy",
    "get_error_recovery",

    # Incremental Memory
    "IncrementalMemorySystem",
    "MemoryBlock",
    "MemoryUpdate",
    "MemoryType",
    "MemoryPriority",
    "get_memory_system",
]