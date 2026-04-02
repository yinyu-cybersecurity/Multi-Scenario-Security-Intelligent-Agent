# State系统
#
# 借鉴Claude Code的状态管理设计

# Claude Code外部Store - 框架无关的状态管理
from .store import (
    Store,
    create_store,
    AppState,
    get_default_app_state,
    get_app_state_store,
)

__all__ = [
    # Claude Code外部Store
    "Store",
    "create_store",
    "AppState",
    "get_default_app_state",
    "get_app_state_store",
]