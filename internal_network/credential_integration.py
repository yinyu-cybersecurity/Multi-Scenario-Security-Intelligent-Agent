# internal_network/credential_integration.py
"""
凭据集成模块

修复凭据管理问题:
1. 凭据解析后自动存储到CredentialManager
2. 横向移动时从CredentialManager获取最佳凭据
3. 统一凭据格式处理
"""
from typing import Dict, List, Optional
from logger import get_logger

logger = get_logger("CredentialIntegration")

# 尝试导入凭据管理器
try:
    from internal_network.credential_manager import (
        get_credential_manager,
        CredentialType,
        PrivilegeLevel,
        Credential
    )
    CREDENTIAL_MANAGER_AVAILABLE = True
except ImportError:
    logger.warning("Credential manager module not available")
    CREDENTIAL_MANAGER_AVAILABLE = False


def store_credentials_to_manager(credentials: List[Dict], source: str = "scan") -> int:
    """
    将凭据列表存储到CredentialManager

    Args:
        credentials: 凭据字典列表，支持多种格式:
            - {"ip": "x.x.x.x", "username": "xxx", "password": "xxx"}
            - {"host": "x.x.x.x", "username": "xxx", "hash": "xxx"}
            - {"username": "xxx", "ntlm_hash": "xxx:xxx", ...}
        source: 凭据来源标识

    Returns:
        成功存储的凭据数量
    """
    if not CREDENTIAL_MANAGER_AVAILABLE or not credentials:
        return 0

    cm = get_credential_manager()
    stored_count = 0

    for cred in credentials:
        try:
            # 统一获取字段，支持多种格式
            host = cred.get("ip") or cred.get("host", "")
            username = cred.get("username", "")
            password = cred.get("password", "")

            # 支持多种hash字段名
            hash_val = (
                cred.get("hash") or
                cred.get("ntlm_hash") or
                cred.get("ntlm_hash", "")
            )

            # 如果hash是LM:NT格式，只取NT部分
            if hash_val and ":" in hash_val and len(hash_val.split(":")) == 2:
                parts = hash_val.split(":")
                # 如果两部分都是有效的哈希，保留完整格式
                if len(parts[0]) == 32 and len(parts[1]) == 32:
                    pass  # 保持完整的LM:NT格式
                elif len(parts[1]) == 32:
                    hash_val = parts[1]  # 只使用NT部分

            domain = cred.get("domain", "")
            port = cred.get("port", 0)
            service = cred.get("service", "")

            if not host or not username:
                continue

            privilege = infer_privilege_from_username(username)

            # 判断凭据类型并存储
            if password:
                cm.add_plaintext(
                    host=host,
                    username=username,
                    password=password,
                    domain=domain,
                    port=port,
                    source=f"{source}/{service}",
                    privilege=privilege
                )
                stored_count += 1
                logger.debug(f"存储明文凭据: {username}@{host}")
            elif hash_val:
                cm.add_ntlm(
                    host=host,
                    username=username,
                    ntlm_hash=hash_val,
                    domain=domain,
                    port=port,
                    source=f"{source}/{service}",
                    privilege=privilege
                )
                stored_count += 1
                logger.debug(f"存储哈希凭据: {username}@{host}")

        except Exception as e:
            logger.debug(f"存储凭据失败: {e}")

    if stored_count > 0:
        logger.info(f"[CredentialManager] 自动存储 {stored_count} 条凭据")

    return stored_count


def infer_privilege_from_username(username: str):
    """
    从用户名推断权限级别

    Args:
        username: 用户名

    Returns:
        PrivilegeLevel枚举值
    """
    if not CREDENTIAL_MANAGER_AVAILABLE:
        return None

    if not username:
        return PrivilegeLevel.USER

    username_lower = username.lower()

    # 域管理员常见名称
    if username_lower in ["administrator", "admin", "root"]:
        return PrivilegeLevel.LOCAL_ADMIN

    # 计算机账户
    if username_lower.endswith("$"):
        return PrivilegeLevel.COMPUTER_ACCOUNT

    # 服务账户
    if any(kw in username_lower for kw in ["svc", "service", "_svc", "serviceaccount"]):
        return PrivilegeLevel.SERVICE_ACCOUNT

    # 管理员关键词
    if any(kw in username_lower for kw in ["admin", "adm", "root"]):
        return PrivilegeLevel.LOCAL_ADMIN

    return PrivilegeLevel.USER


def get_credentials_for_lateral(state: Dict, target: str) -> List[Dict]:
    """
    获取用于横向移动的凭据

    优先从CredentialManager获取，降级使用state中的凭据

    Args:
        state: 当前状态字典
        target: 目标主机IP

    Returns:
        凭据字典列表
    """
    # 优先从CredentialManager获取
    if CREDENTIAL_MANAGER_AVAILABLE:
        cm = get_credential_manager()

        # 尝试获取目标的最佳凭据
        for service in ["smb", "winrm", "wmi", "ssh"]:
            cred = cm.get_best_for_target(target, service)
            if cred:
                logger.info(f"[CredentialManager] 获取最佳凭据: {cred.username}@{cred.host} for {service}")
                return [credential_to_dict(cred)]

        # 尝试获取用于横向移动的最佳凭据
        lateral_cred = cm.get_best_for_lateral()
        if lateral_cred:
            logger.info(f"[CredentialManager] 获取横向凭据: {lateral_cred.username}@{lateral_cred.host}")
            return [credential_to_dict(lateral_cred)]

        # 获取所有未使用的凭据
        unused_creds = cm.get_unused()
        if unused_creds:
            logger.info(f"[CredentialManager] 获取 {len(unused_creds)} 条未使用凭据")
            return [credential_to_dict(c) for c in unused_creds]

        # 获取所有凭据
        all_creds = cm.get_all()
        if all_creds:
            logger.info(f"[CredentialManager] 获取所有 {len(all_creds)} 条凭据")
            return [credential_to_dict(c) for c in all_creds]

    # 降级使用state中的凭据
    state_creds = state.get("credentials") or []
    if state_creds:
        logger.info(f"[State] 使用state中的 {len(state_creds)} 条凭据")
    return state_creds


def credential_to_dict(cred) -> Dict:
    """
    将Credential对象转换为字典格式

    统一凭据格式，便于不同模块使用

    Args:
        cred: Credential对象

    Returns:
        凭据字典
    """
    return {
        "host": cred.host,
        "username": cred.username,
        "password": cred.password,
        "hash": cred.ntlm_hash,
        "domain": cred.domain,
        "port": cred.port,
        "cred_type": cred.cred_type.value if hasattr(cred.cred_type, 'value') else str(cred.cred_type),
        "privilege": cred.privilege.value if hasattr(cred.privilege, 'value') else str(cred.privilege),
        "verified": cred.verified,
        "used": cred.used
    }


def normalize_credential(cred: Dict) -> Dict:
    """
    标准化凭据格式

    统一不同来源的凭据格式

    Args:
        cred: 原始凭据字典

    Returns:
        标准化后的凭据字典
    """
    normalized = {
        "host": cred.get("ip") or cred.get("host", ""),
        "username": cred.get("username", ""),
        "password": cred.get("password", ""),
        "hash": cred.get("hash") or cred.get("ntlm_hash", ""),
        "domain": cred.get("domain", ""),
        "port": cred.get("port", 0),
        "service": cred.get("service", ""),
        "cred_type": cred.get("cred_type", "plaintext"),
    }

    # 如果有hash但格式不对，尝试修复
    if normalized["hash"] and ":" in normalized["hash"]:
        parts = normalized["hash"].split(":")
        if len(parts) == 2:
            # 标准LM:NT格式
            normalized["hash"] = f"{parts[0]}:{parts[1]}"

    return normalized


def parse_secretsdump_output(output: str, host: str) -> List[Dict]:
    """
    解析secretsdump输出，提取凭据

    Args:
        output: secretsdump命令输出
        host: 目标主机

    Returns:
        凭据字典列表
    """
    import re
    credentials = []

    # NTLM哈希格式: username:rid:lm:ntlm:::
    ntlm_pattern = r'^(\w+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::'
    # 清理哈希格式: username:lm:ntlm
    clean_pattern = r'^(\w+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})$'

    for line in output.split('\n'):
        line = line.strip()

        # 尝试匹配完整格式
        match = re.match(ntlm_pattern, line)
        if match:
            username, rid, lm, ntlm = match.groups()
            credentials.append({
                "host": host,
                "username": username,
                "hash": f"{lm}:{ntlm}",
                "ntlm_hash": ntlm,
                "rid": rid,
                "cred_type": "ntlm",
                "source": "secretsdump"
            })
            continue

        # 尝试匹配清理格式
        match = re.match(clean_pattern, line)
        if match:
            username, lm, ntlm = match.groups()
            credentials.append({
                "host": host,
                "username": username,
                "hash": f"{lm}:{ntlm}",
                "ntlm_hash": ntlm,
                "cred_type": "ntlm",
                "source": "secretsdump"
            })

    # 自动存储
    if credentials:
        store_credentials_to_manager(credentials, source="secretsdump")

    return credentials


def parse_mimikatz_output(output: str, host: str) -> List[Dict]:
    """
    解析mimikatz输出，提取凭据

    Args:
        output: mimikatz命令输出
        host: 目标主机

    Returns:
        凭据字典列表
    """
    import re
    credentials = []

    # mimikatz格式: * Username : xxx
    #               * Domain   : xxx
    #               * Password : xxx
    # 或 NTLM: username::domain:lm:ntlm

    # NTLM哈希
    ntlm_pattern = r'(\w+)::(\w+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})'
    for match in re.finditer(ntlm_pattern, output):
        username, domain, lm, ntlm, _ = match.groups()
        credentials.append({
            "host": host,
            "username": username,
            "domain": domain,
            "hash": f"{lm}:{ntlm}",
            "ntlm_hash": ntlm,
            "cred_type": "ntlm",
            "source": "mimikatz"
        })

    # 明文密码
    user_match = None
    for line in output.split('\n'):
        line = line.strip()

        if 'Username' in line:
            user_match = line.split(':')[-1].strip()
        elif 'Domain' in line and user_match:
            domain = line.split(':')[-1].strip()
        elif 'Password' in line and user_match:
            password = line.split(':')[-1].strip()
            if password and password != '(null)':
                credentials.append({
                    "host": host,
                    "username": user_match,
                    "password": password,
                    "domain": domain if 'domain' in dir() else "",
                    "cred_type": "plaintext",
                    "source": "mimikatz"
                })

    # 自动存储
    if credentials:
        store_credentials_to_manager(credentials, source="mimikatz")

    return credentials


# 便捷导入函数
def get_credential_manager_safe():
    """安全获取CredentialManager实例"""
    if CREDENTIAL_MANAGER_AVAILABLE:
        return get_credential_manager()
    return None


