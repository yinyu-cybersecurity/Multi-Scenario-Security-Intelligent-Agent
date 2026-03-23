# internal_network/credential_manager.py
"""
凭据管理模块

功能：
- 收集并管理域内凭据
- 凭据优先级排序
- 凭据有效性验证
- 支持多种凭据类型
"""

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CredentialType(Enum):
    """凭据类型"""
    PLAINTEXT = "plaintext"
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    SSH_KEY = "ssh_key"
    HASH = "hash"
    TICKET = "ticket"


class PrivilegeLevel(Enum):
    """权限级别"""
    DOMAIN_ADMIN = "domain_admin"
    LOCAL_ADMIN = "local_admin"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    COMPUTER_ACCOUNT = "computer_account"


@dataclass
class Credential:
    """凭据数据类"""
    host: str
    username: str
    cred_type: CredentialType
    privilege: PrivilegeLevel = PrivilegeLevel.USER
    password: str = ""
    ntlm_hash: str = ""
    ssh_key: str = ""
    ticket_path: str = ""
    domain: str = ""
    port: int = 0
    source: str = ""
    obtained_at: str = ""
    verified: bool = False
    used: bool = False
    notes: str = ""

    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            "host": self.host,
            "username": self.username,
            "cred_type": self.cred_type.value,
            "privilege": self.privilege.value,
            "password": self.password,
            "ntlm_hash": self.ntlm_hash,
            "ssh_key": self.ssh_key,
            "ticket_path": self.ticket_path,
            "domain": self.domain,
            "port": self.port,
            "source": self.source,
            "obtained_at": self.obtained_at,
            "verified": self.verified,
            "used": self.used,
            "notes": self.notes
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Credential":
        """从字典创建"""
        return cls(
            host=data.get("host", ""),
            username=data.get("username", ""),
            cred_type=CredentialType(data.get("cred_type", "plaintext")),
            privilege=PrivilegeLevel(data.get("privilege", "user")),
            password=data.get("password", ""),
            ntlm_hash=data.get("ntlm_hash", ""),
            ssh_key=data.get("ssh_key", ""),
            ticket_path=data.get("ticket_path", ""),
            domain=data.get("domain", ""),
            port=data.get("port", 0),
            source=data.get("source", ""),
            obtained_at=data.get("obtained_at", ""),
            verified=data.get("verified", False),
            used=data.get("used", False),
            notes=data.get("notes", "")
        )


class CredentialManager:
    """
    凭据管理器

    统一管理渗透测试过程中获取的所有凭据
    """

    # 权限优先级
    PRIVILEGE_PRIORITY = {
        PrivilegeLevel.DOMAIN_ADMIN: 4,
        PrivilegeLevel.LOCAL_ADMIN: 3,
        PrivilegeLevel.USER: 2,
        PrivilegeLevel.SERVICE_ACCOUNT: 1,
        PrivilegeLevel.COMPUTER_ACCOUNT: 0
    }

    def __init__(self, storage_file: str = ".memory/credentials.json"):
        self.storage_file = storage_file
        self.credentials: List[Credential] = []
        self._load_credentials()

    def _load_credentials(self):
        """从文件加载凭据"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.credentials = [
                        Credential.from_dict(c) for c in data
                    ]
            except Exception as e:
                print(f"[CredentialManager] 加载凭据失败: {e}")

    def _save_credentials(self):
        """保存凭据到文件"""
        os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump(
                    [c.to_dict() for c in self.credentials],
                    f,
                    ensure_ascii=False,
                    indent=2
                )
        except Exception as e:
            print(f"[CredentialManager] 保存凭据失败: {e}")

    # =========================================================================
    # 添加凭据
    # =========================================================================

    def add_plaintext(self, host: str, username: str, password: str,
                      domain: str = "", port: int = 0,
                      privilege: PrivilegeLevel = PrivilegeLevel.USER,
                      source: str = "") -> bool:
        """添加明文凭据"""
        cred = Credential(
            host=host,
            username=username,
            password=password,
            cred_type=CredentialType.PLAINTEXT,
            privilege=privilege,
            domain=domain,
            port=port,
            source=source,
            obtained_at=datetime.now().isoformat()
        )
        return self._add_credential(cred)

    def add_ntlm(self, host: str, username: str, ntlm_hash: str,
                 domain: str = "", port: int = 0,
                 privilege: PrivilegeLevel = PrivilegeLevel.USER,
                 source: str = "") -> bool:
        """添加NTLM哈希凭据"""
        cred = Credential(
            host=host,
            username=username,
            ntlm_hash=ntlm_hash,
            cred_type=CredentialType.NTLM,
            privilege=privilege,
            domain=domain,
            port=port,
            source=source,
            obtained_at=datetime.now().isoformat()
        )
        return self._add_credential(cred)

    def add_kerberos_ticket(self, host: str, username: str,
                            ticket_path: str, domain: str = "",
                            privilege: PrivilegeLevel = PrivilegeLevel.USER,
                            source: str = "") -> bool:
        """添加Kerberos票据"""
        cred = Credential(
            host=host,
            username=username,
            ticket_path=ticket_path,
            cred_type=CredentialType.KERBEROS,
            privilege=privilege,
            domain=domain,
            source=source,
            obtained_at=datetime.now().isoformat()
        )
        return self._add_credential(cred)

    def add_ssh_key(self, host: str, username: str, ssh_key: str,
                    port: int = 22, privilege: PrivilegeLevel = PrivilegeLevel.USER,
                    source: str = "") -> bool:
        """添加SSH密钥"""
        cred = Credential(
            host=host,
            username=username,
            ssh_key=ssh_key,
            cred_type=CredentialType.SSH_KEY,
            privilege=privilege,
            port=port,
            source=source,
            obtained_at=datetime.now().isoformat()
        )
        return self._add_credential(cred)

    def _add_credential(self, cred: Credential) -> bool:
        """添加凭据（内部方法）"""
        # 检查是否已存在
        for existing in self.credentials:
            if (existing.host == cred.host and
                existing.username == cred.username and
                existing.cred_type == cred.cred_type):
                # 更新现有凭据
                existing.password = cred.password or existing.password
                existing.ntlm_hash = cred.ntlm_hash or existing.ntlm_hash
                existing.privilege = max(
                    existing.privilege,
                    cred.privilege,
                    key=lambda p: self.PRIVILEGE_PRIORITY[p]
                )
                self._save_credentials()
                return True

        # 添加新凭据
        self.credentials.append(cred)
        self._save_credentials()
        print(f"[CredentialManager] 添加凭据: {cred.username}@{cred.host}")
        return True

    # =========================================================================
    # 查询凭据
    # =========================================================================

    def get_all(self) -> List[Credential]:
        """获取所有凭据"""
        return self.credentials

    def get_by_host(self, host: str) -> List[Credential]:
        """按主机筛选"""
        return [c for c in self.credentials if c.host == host]

    def get_by_domain(self, domain: str) -> List[Credential]:
        """按域筛选"""
        return [c for c in self.credentials if c.domain == domain]

    def get_by_type(self, cred_type: CredentialType) -> List[Credential]:
        """按类型筛选"""
        return [c for c in self.credentials if c.cred_type == cred_type]

    def get_by_privilege(self, privilege: PrivilegeLevel) -> List[Credential]:
        """按权限级别筛选"""
        return [c for c in self.credentials if c.privilege == privilege]

    def get_domain_admins(self) -> List[Credential]:
        """获取域管凭据"""
        return [c for c in self.credentials
                if c.privilege == PrivilegeLevel.DOMAIN_ADMIN]

    def get_local_admins(self) -> List[Credential]:
        """获取本地管理员凭据"""
        return [c for c in self.credentials
                if c.privilege == PrivilegeLevel.LOCAL_ADMIN]

    def get_unused(self) -> List[Credential]:
        """获取未使用的凭据"""
        return [c for c in self.credentials if not c.used]

    # =========================================================================
    # 智能选择
    # =========================================================================

    def get_best_for_target(self, target: str, service: str) -> Optional[Credential]:
        """
        为目标选择最佳凭据

        Args:
            target: 目标主机
            service: 服务类型 (smb/winrm/ssh/mysql等)

        Returns:
            最佳凭据或None
        """
        # 获取目标相关凭据
        target_creds = self.get_by_host(target)

        if not target_creds:
            # 尝试使用域凭据
            target_creds = [c for c in self.credentials if c.domain]

        if not target_creds:
            return None

        # 服务适用的凭据类型
        service_types = {
            "smb": [CredentialType.PLAINTEXT, CredentialType.NTLM, CredentialType.KERBEROS],
            "winrm": [CredentialType.PLAINTEXT, CredentialType.NTLM, CredentialType.KERBEROS],
            "wmi": [CredentialType.PLAINTEXT, CredentialType.NTLM, CredentialType.KERBEROS],
            "rdp": [CredentialType.PLAINTEXT, CredentialType.NTLM],
            "ssh": [CredentialType.PLAINTEXT, CredentialType.SSH_KEY],
            "mysql": [CredentialType.PLAINTEXT],
            "mssql": [CredentialType.PLAINTEXT],
            "redis": [CredentialType.PLAINTEXT],
            "mongodb": [CredentialType.PLAINTEXT],
        }

        allowed_types = service_types.get(service, [CredentialType.PLAINTEXT])

        # 筛选可用凭据
        usable = [c for c in target_creds
                  if c.cred_type in allowed_types and not c.used]

        if not usable:
            usable = [c for c in target_creds
                      if c.cred_type in allowed_types]

        if not usable:
            return None

        # 按权限排序
        usable.sort(
            key=lambda c: self.PRIVILEGE_PRIORITY.get(c.privilege, 0),
            reverse=True
        )

        return usable[0]

    def get_best_for_lateral(self) -> Optional[Credential]:
        """
        获取用于横向移动的最佳凭据

        优先级：域管 > 本地管 > 普通用户
        """
        unused = self.get_unused()

        if not unused:
            unused = self.credentials

        # 优先域管
        domain_admins = [c for c in unused
                        if c.privilege == PrivilegeLevel.DOMAIN_ADMIN]
        if domain_admins:
            return domain_admins[0]

        # 其次本地管
        local_admins = [c for c in unused
                       if c.privilege == PrivilegeLevel.LOCAL_ADMIN]
        if local_admins:
            return local_admins[0]

        # 最后普通用户
        users = [c for c in unused
                 if c.privilege == PrivilegeLevel.USER]
        if users:
            return users[0]

        return None

    # =========================================================================
    # 状态更新
    # =========================================================================

    def mark_used(self, host: str, username: str):
        """标记凭据已使用"""
        for cred in self.credentials:
            if cred.host == host and cred.username == username:
                cred.used = True
        self._save_credentials()

    def mark_verified(self, host: str, username: str, success: bool):
        """标记凭据验证状态"""
        for cred in self.credentials:
            if cred.host == host and cred.username == username:
                cred.verified = success
        self._save_credentials()

    def update_privilege(self, host: str, username: str,
                        privilege: PrivilegeLevel):
        """更新权限级别"""
        for cred in self.credentials:
            if cred.host == host and cred.username == username:
                cred.privilege = privilege
        self._save_credentials()

    # =========================================================================
    # 统计和导出
    # =========================================================================

    def get_stats(self) -> Dict:
        """获取凭据统计"""
        stats = {
            "total": len(self.credentials),
            "by_type": {},
            "by_privilege": {},
            "verified": 0,
            "used": 0,
            "domains": set()
        }

        for cred in self.credentials:
            # 按类型统计
            type_name = cred.cred_type.value
            stats["by_type"][type_name] = stats["by_type"].get(type_name, 0) + 1

            # 按权限统计
            priv_name = cred.privilege.value
            stats["by_privilege"][priv_name] = stats["by_privilege"].get(priv_name, 0) + 1

            # 统计
            if cred.verified:
                stats["verified"] += 1
            if cred.used:
                stats["used"] += 1
            if cred.domain:
                stats["domains"].add(cred.domain)

        stats["domains"] = list(stats["domains"])
        return stats

    def export_for_impacket(self) -> List[str]:
        """
        导出impacket格式的凭据

        Returns:
            格式化的凭据字符串列表
        """
        lines = []
        for cred in self.credentials:
            if cred.password:
                lines.append(f"{cred.domain}/{cred.username}:{cred.password}@{cred.host}")
            elif cred.ntlm_hash:
                lines.append(f"{cred.domain}/{cred.username}@{cred.host} -hashes :{cred.ntlm_hash}")
        return lines

    def export_for_crackmap(self) -> List[str]:
        """导出crackmapexec格式"""
        lines = []
        for cred in self.credentials:
            if cred.password:
                lines.append(f"{cred.username}:{cred.password}")
            elif cred.ntlm_hash:
                lines.append(f"{cred.username}:{cred.ntlm_hash}")
        return lines

    def clear(self):
        """清空所有凭据"""
        self.credentials = []
        self._save_credentials()


# 全局实例
_credential_manager = None


def get_credential_manager() -> CredentialManager:
    """获取全局凭据管理器"""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager


# 便捷函数
def add_credential(host: str, username: str, password: str = None,
                   ntlm_hash: str = None, domain: str = "",
                   privilege: PrivilegeLevel = PrivilegeLevel.USER,
                   source: str = "") -> bool:
    """添加凭据便捷函数"""
    cm = get_credential_manager()

    if password:
        return cm.add_plaintext(host, username, password, domain,
                                privilege=privilege, source=source)
    elif ntlm_hash:
        return cm.add_ntlm(host, username, ntlm_hash, domain,
                          privilege=privilege, source=source)

    return False


def get_best_credential(target: str, service: str) -> Optional[Credential]:
    """获取最佳凭据便捷函数"""
    return get_credential_manager().get_best_for_target(target, service)


def register():
    """注册凭据管理器"""
    pass