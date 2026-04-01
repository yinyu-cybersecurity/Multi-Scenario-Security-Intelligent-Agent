# Coordinator系统
#
# 借鉴Claude Code的多Agent协调机制

from .dispatcher import (
    CoordinatorDispatcher,
    ForkTask,
    CoordinatorSession,
    get_coordinator_dispatcher,
    parallel_scan_targets,
    run_autonomous_attack_coordinated,
)

__all__ = [
    "CoordinatorDispatcher",
    "ForkTask",
    "CoordinatorSession",
    "get_coordinator_dispatcher",
    "parallel_scan_targets",
    "run_autonomous_attack_coordinated",
]