# app/state_types/internal_network.py
"""
内网渗透场景状态

内网渗透测试专用的状态字段。
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict
from .reducers import (
    cap_list_reducer,
    credentials_reducer,
    internal_hosts_reducer,
)


class InternalHost(TypedDict):
    """
    内网主机信息

    Attributes:
        ip: IP 地址
        hostname: 主机名
        os: 操作系统
        ports: 端口列表
        domain: 所属域
        is_dc: 是否是域控
    """
    ip: str
    hostname: str
    os: str
    ports: List[Dict]
    domain: str
    is_dc: bool


class Credential(TypedDict):
    """
    凭据信息

    Attributes:
        host: 主机地址
        username: 用户名
        password: 明文密码
        hash: 哈希值
        domain: 域名
        cred_type: 凭据类型
    """
    host: str
    username: str
    password: Optional[str]
    hash: Optional[str]
    domain: Optional[str]
    cred_type: Literal['plaintext', 'ntlm', 'kerberos', 'ssh_key', 'password_hash']


class LateralMove(TypedDict):
    """
    横向移动记录

    Attributes:
        source_host: 源主机
        target_host: 目标主机
        method: 移动方法
        credential_used: 使用的凭据
        success: 是否成功
        timestamp: 时间戳
    """
    source_host: str
    target_host: str
    method: str
    credential_used: str
    success: bool
    timestamp: float


class InternalNetworkState(TypedDict):
    """
    内网渗透场景状态

    包含内网渗透所需的所有字段。

    主要模块:
    - 内网发现
    - 凭据管理
    - 会话管理
    - AD 域信息
    - 横向移动
    - 后渗透状态
    """

    # =========================================================================
    # 内网发现
    # =========================================================================

    # 发现的内网主机
    internal_hosts: Annotated[List[Dict], internal_hosts_reducer]

    # 内网网段范围
    internal_network_range: str

    # 域控 IP 或主机名
    domain_controller: str

    # =========================================================================
    # 凭据管理
    # =========================================================================

    # 已获取的凭据
    credentials: Annotated[List[Dict], credentials_reducer]

    # =========================================================================
    # 会话管理
    # =========================================================================

    # 活跃的渗透会话
    active_sessions: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 10)]

    # =========================================================================
    # AD 域信息
    # =========================================================================

    # AD 域名
    ad_domain: str

    # 域用户
    ad_users: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]

    # 域组
    ad_groups: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]

    # 域计算机
    ad_computers: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]

    # 域信任关系
    ad_trusts: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 10)]

    # =========================================================================
    # 横向移动
    # =========================================================================

    # 横向移动路径
    lateral_movement_paths: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 20)]

    # =========================================================================
    # 内网渗透模式控制
    # =========================================================================

    # 是否处于内网渗透模式
    internal_mode: bool

    # 当前内网目标
    current_internal_target: str

    # 跳板机
    pivot_host: str

    # =========================================================================
    # 后渗透状态
    # =========================================================================

    # Shell 会话信息
    shell_session: Dict[str, Any]

    # 后渗透处理状态
    post_exploit_status: str

    # 工具上传状态
    upload_status: str

    # 隧道状态
    tunnel_status: str

    # SOCKS5 代理信息
    proxy_info: Dict[str, Any]