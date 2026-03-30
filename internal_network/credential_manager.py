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
from collections import defaultdict
try:
    from app.logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger("Credential")


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
                logger.warning(f"加载凭据失败: {e}")

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
            logger.warning(f"保存凭据失败: {e}")

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
        logger.info(f"添加凭据: {cred.username}@{cred.host}")
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

    # =========================================================================
    # 凭据-主机映射（新增功能）
    # =========================================================================

    def get_credential_host_mapping(self) -> Dict[str, List[str]]:
        """
        构建凭据到主机的映射

        Returns:
            {credential_id: [host1, host2, ...]}
        """
        mapping = defaultdict(list)

        for cred in self.credentials:
            cred_id = f"{cred.username}@{cred.domain or 'local'}"

            # 直接关联的主机
            if cred.host:
                mapping[cred_id].append(cred.host)

            # 域凭据可能适用于所有域主机
            if cred.domain and cred.privilege in [PrivilegeLevel.DOMAIN_ADMIN, PrivilegeLevel.LOCAL_ADMIN]:
                # 标记为域范围凭据
                mapping[cred_id].append(f"domain:{cred.domain}")

        return dict(mapping)

    def infer_credential_scope(self, cred: Credential, known_hosts: List[str]) -> List[str]:
        """
        推断凭据的适用范围

        Args:
            cred: 凭据对象
            known_hosts: 已知主机列表

        Returns:
            可能适用该凭据的主机列表
        """
        applicable_hosts = []

        # 域管凭据适用于所有域主机
        if cred.privilege == PrivilegeLevel.DOMAIN_ADMIN and cred.domain:
            # 返回所有同域主机
            applicable_hosts = [h for h in known_hosts]
            logger.info(f"[CredentialManager] 域管凭据 {cred.username} 可能适用于 {len(applicable_hosts)} 台主机")

        # 本地管理员凭据可能复用
        elif cred.privilege == PrivilegeLevel.LOCAL_ADMIN:
            # 检查是否是常见本地管理员账户
            common_admins = ["administrator", "admin", "root"]
            if cred.username.lower() in common_admins:
                logger.info(f"[CredentialManager] 常见管理员账户 {cred.username} 可能可在其他主机复用")
                applicable_hosts = [h for h in known_hosts if h != cred.host]

        # 服务账户可能在多台主机有效
        elif cred.privilege == PrivilegeLevel.SERVICE_ACCOUNT:
            # 服务账户通常在特定服务相关主机有效
            if cred.domain:
                applicable_hosts = [h for h in known_hosts]

        return applicable_hosts

    def suggest_credential_reuse(self, target_host: str, known_hosts: List[str]) -> List[Dict]:
        """
        建议可用于目标主机的凭据

        Args:
            target_host: 目标主机IP
            known_hosts: 已知所有主机列表

        Returns:
            建议的凭据列表，包含复用可能性
        """
        suggestions = []

        # 1. 直接匹配的凭据
        direct_creds = self.get_by_host(target_host)
        for cred in direct_creds:
            suggestions.append({
                "credential": cred.to_dict(),
                "confidence": 1.0,
                "reason": "凭据直接关联此主机"
            })

        # 2. 域凭据
        domain_creds = [c for c in self.credentials if c.domain]
        for cred in domain_creds:
            if cred not in direct_creds:
                confidence = 0.9 if cred.privilege == PrivilegeLevel.DOMAIN_ADMIN else 0.7
                suggestions.append({
                    "credential": cred.to_dict(),
                    "confidence": confidence,
                    "reason": f"域凭据，权限: {cred.privilege.value}"
                })

        # 3. 可能复用的本地凭据
        local_admins = self.get_local_admins()
        for cred in local_admins:
            if cred.host != target_host:
                suggestions.append({
                    "credential": cred.to_dict(),
                    "confidence": 0.5,
                    "reason": "本地管理员凭据，可能可复用"
                })

        # 按置信度排序
        suggestions.sort(key=lambda x: x["confidence"], reverse=True)
        return suggestions

    def get_attack_paths_with_credentials(self, target_hosts: List[str]) -> List[Dict]:
        """
        基于凭据生成攻击路径

        Args:
            target_hosts: 目标主机列表

        Returns:
            攻击路径列表，每条路径包含使用的凭据
        """
        paths = []

        for target in target_hosts:
            suggestions = self.suggest_credential_reuse(target, target_hosts)

            if suggestions:
                best = suggestions[0]
                paths.append({
                    "target": target,
                    "credential": best["credential"],
                    "confidence": best["confidence"],
                    "reason": best["reason"],
                    "attack_methods": self._suggest_attack_methods(target, best["credential"])
                })

        return paths

    def _suggest_attack_methods(self, target: str, cred: Dict) -> List[str]:
        """根据凭据类型建议攻击方法"""
        methods = []
        cred_type = cred.get("cred_type", "plaintext")

        if cred_type in ["plaintext", "ntlm"]:
            methods.extend(["smb", "winrm", "wmi", "psexec"])

        if cred_type == "kerberos":
            methods.append("kerberos")

        if cred_type == "ssh_key":
            methods.append("ssh")

        return methods

    def export_for_attack_graph(self, known_hosts: List[str]) -> Dict:
        """
        导出供攻击图使用的数据

        Args:
            known_hosts: 已知主机列表

        Returns:
            攻击图友好的凭据数据
        """
        edges = []

        for cred in self.credentials:
            scope = self.infer_credential_scope(cred, known_hosts)

            for target in scope:
                edges.append({
                    "source": cred.host,
                    "target": target,
                    "credential": f"{cred.username}@{cred.domain or 'local'}",
                    "credential_type": cred.cred_type.value,
                    "privilege": cred.privilege.value,
                    "methods": self._suggest_attack_methods(target, cred.to_dict())
                })

        return {
            "credentials": [c.to_dict() for c in self.credentials],
            "attack_edges": edges
        }

    # =========================================================================
    # 凭据验证
    # =========================================================================

    def verify_credential(self, cred: Credential, service: str = "smb") -> Dict:
        """
        验证凭据有效性

        Args:
            cred: 凭据对象
            service: 验证服务类型 (smb/winrm/ssh/rdp)

        Returns:
            {
                "valid": bool,
                "privilege": str,
                "error": str
            }
        """
        import socket

        result = {
            "valid": False,
            "privilege": cred.privilege.value,
            "error": None
        }

        # 根据服务类型验证
        if service == "smb":
            return self._verify_smb_credential(cred)
        elif service == "winrm":
            return self._verify_winrm_credential(cred)
        elif service == "ssh":
            return self._verify_ssh_credential(cred)
        elif service == "rdp":
            return self._verify_rdp_credential(cred)
        else:
            result["error"] = f"不支持的服务类型: {service}"
            return result

    def _verify_smb_credential(self, cred: Credential) -> Dict:
        """验证SMB凭据"""
        result = {"valid": False, "privilege": cred.privilege.value, "error": None}

        try:
            # 尝试使用impacket或crackmapexec验证
            from tool_framework import ToolRegistry

            if cred.password:
                # 明文凭据
                cmd_result = ToolRegistry.execute_cached(
                    "crackmapexec",
                    cred.host,
                    {
                        "protocol": "smb",
                        "target": cred.host,
                        "username": cred.username,
                        "password": cred.password,
                        "domain": cred.domain
                    }
                )
            elif cred.ntlm_hash:
                # NTLM哈希
                cmd_result = ToolRegistry.execute_cached(
                    "crackmapexec",
                    cred.host,
                    {
                        "protocol": "smb",
                        "target": cred.host,
                        "username": cred.username,
                        "hash": cred.ntlm_hash,
                        "domain": cred.domain
                    }
                )
            else:
                result["error"] = "无可用凭据数据"
                return result

            # 解析结果
            if cmd_result.get("success"):
                output = str(cmd_result.get("result", ""))

                # 检查是否成功
                if "[+]" in output or "Pwn3d!" in output:
                    result["valid"] = True

                    # 检查权限
                    if "Pwn3d!" in output or "ADMIN" in output:
                        result["privilege"] = "local_admin"
                        cred.privilege = PrivilegeLevel.LOCAL_ADMIN
                    elif "DOMAIN ADMIN" in output.upper():
                        result["privilege"] = "domain_admin"
                        cred.privilege = PrivilegeLevel.DOMAIN_ADMIN

                    self.mark_verified(cred.host, cred.username, True)
                else:
                    result["error"] = "凭据无效"
                    self.mark_verified(cred.host, cred.username, False)
            else:
                result["error"] = cmd_result.get("error", "验证失败")

        except ImportError:
            result["error"] = "crackmapexec工具不可用"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _verify_winrm_credential(self, cred: Credential) -> Dict:
        """验证WinRM凭据"""
        result = {"valid": False, "privilege": cred.privilege.value, "error": None}

        try:
            from tool_framework import ToolRegistry

            if cred.password:
                cmd_result = ToolRegistry.execute_cached(
                    "crackmapexec",
                    cred.host,
                    {
                        "protocol": "winrm",
                        "target": cred.host,
                        "username": cred.username,
                        "password": cred.password,
                        "domain": cred.domain
                    }
                )
            else:
                result["error"] = "WinRM需要明文凭据"
                return result

            if cmd_result.get("success"):
                output = str(cmd_result.get("result", ""))
                if "[+]" in output:
                    result["valid"] = True
                    self.mark_verified(cred.host, cred.username, True)
                else:
                    result["error"] = "WinRM凭据无效"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _verify_ssh_credential(self, cred: Credential) -> Dict:
        """验证SSH凭据"""
        result = {"valid": False, "privilege": cred.privilege.value, "error": None}

        try:
            import paramiko

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            port = cred.port or 22

            if cred.password:
                client.connect(cred.host, port=port,
                              username=cred.username,
                              password=cred.password,
                              timeout=10)
            elif cred.ssh_key:
                import io
                key = paramiko.RSAKey.from_private_key_file(io.StringIO(cred.ssh_key))
                client.connect(cred.host, port=port,
                              username=cred.username,
                              pkey=key,
                              timeout=10)
            else:
                result["error"] = "SSH需要密码或密钥"
                return result

            # 验证成功，检查权限
            stdin, stdout, stderr = client.exec_command("id")
            output = stdout.read().decode()

            result["valid"] = True

            if "root" in output or "wheel" in output:
                result["privilege"] = "local_admin"
                cred.privilege = PrivilegeLevel.LOCAL_ADMIN

            client.close()
            self.mark_verified(cred.host, cred.username, True)

        except ImportError:
            result["error"] = "paramiko库不可用"
        except Exception as e:
            result["error"] = str(e)
            self.mark_verified(cred.host, cred.username, False)

        return result

    def _verify_rdp_credential(self, cred: Credential) -> Dict:
        """
        验证RDP凭据 - 完整实现

        使用xfreerdp验证凭据有效性
        """
        result = {"valid": False, "privilege": cred.privilege.value, "error": None}

        # Step 1: 检查端口可达性
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            code = sock.connect_ex((cred.host, 3389))
            sock.close()

            if code != 0:
                result["error"] = "RDP端口(3389)不可达"
                return result
        except Exception as e:
            result["error"] = f"端口检查失败: {str(e)}"
            return result

        # Step 2: 检查xfreerdp工具
        xfreerdp_available = self._check_xfreerdp()
        if not xfreerdp_available:
            # 降级方案：只报告端口可达
            result["valid"] = True
            result["error"] = "RDP端口可达，但xfreerdp不可用，无法完整验证凭据"
            result["warning"] = "建议安装freerdp2-x11以完整验证"
            return result

        # Step 3: 使用xfreerdp验证凭据
        if not cred.password:
            result["error"] = "RDP验证需要明文凭据"
            return result

        verify_result = self._verify_with_xfreerdp(cred)
        if verify_result.get("valid"):
            result["valid"] = True
            self.mark_verified(cred.host, cred.username, True)

            # 检查权限提升
            if verify_result.get("is_admin"):
                result["privilege"] = "local_admin"
                cred.privilege = PrivilegeLevel.LOCAL_ADMIN
        else:
            result["error"] = verify_result.get("error", "凭据验证失败")
            self.mark_verified(cred.host, cred.username, False)

        return result

    def _check_xfreerdp(self) -> bool:
        """检查xfreerdp是否可用"""
        import subprocess
        try:
            subprocess.run(
                ["xfreerdp", "/version"],
                capture_output=True,
                timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _verify_with_xfreerdp(self, cred: Credential) -> Dict:
        """使用xfreerdp验证凭据"""
        import subprocess
        result = {"valid": False, "error": None, "is_admin": False}

        # 构建验证命令 - 使用非交互模式
        cmd = [
            "xfreerdp",
            f"/u:{cred.username}",
            f"/p:{cred.password}",
            f"/v:{cred.host}",
            "/nosc",  # 不获取桌面
            "/sec:nla",  # NLA认证
            "/cert-ignore",
            "+auth-only",  # 仅认证（新版支持）
            "/timeout:10000"
        ]

        if cred.domain:
            cmd.insert(3, f"/d:{cred.domain}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
                text=True
            )

            output = proc.stdout + proc.stderr

            # 成功标志
            success_indicators = [
                "Authentication successful",
                proc.returncode == 0
            ]
            if any(success_indicators):
                result["valid"] = True
                # 管理员检测 - 通过输出或后续查询
                if "ADMIN" in output.upper() or "administrators" in output.lower():
                    result["is_admin"] = True
                return result

            # 失败标志
            failed_indicators = [
                "Authentication failed",
                "Access denied",
                "Logon failure",
                "wrong password",
                "invalid credentials",
                "STATUS_LOGON_FAILURE"
            ]
            for ind in failed_indicators:
                if ind.lower() in output.lower():
                    result["error"] = f"认证失败: {ind}"
                    return result

            # 未知状态
            result["error"] = f"验证结果未知 (rc={proc.returncode})"
            result["output"] = output[:300]

        except subprocess.TimeoutExpired:
            result["error"] = "验证超时(30秒)"
        except Exception as e:
            result["error"] = f"验证异常: {str(e)}"

        return result

    def verify_all_credentials(self, service: str = "smb") -> Dict:
        """
        验证所有凭据

        Args:
            service: 验证服务类型

        Returns:
            验证结果统计
        """
        results = {
            "total": len(self.credentials),
            "valid": 0,
            "invalid": 0,
            "error": 0,
            "details": []
        }

        for cred in self.credentials:
            verify_result = self.verify_credential(cred, service)

            detail = {
                "host": cred.host,
                "username": cred.username,
                "valid": verify_result["valid"],
                "privilege": verify_result["privilege"],
                "error": verify_result.get("error")
            }

            results["details"].append(detail)

            if verify_result["valid"]:
                results["valid"] += 1
            elif verify_result.get("error"):
                results["error"] += 1
            else:
                results["invalid"] += 1

        logger.info(f"[CredentialManager] 验证完成: {results['valid']}/{results['total']} 有效")

        return results

    def get_verified_credentials(self) -> List[Credential]:
        """获取已验证有效的凭据"""
        return [c for c in self.credentials if c.verified]

    def cleanup_invalid_credentials(self) -> int:
        """
        清理无效凭据

        Returns:
            删除的凭据数量
        """
        initial_count = len(self.credentials)

        # 删除验证失败且过期的凭据
        self.credentials = [
            c for c in self.credentials
            if c.verified or not c.used  # 保留已验证或未使用的
        ]

        removed = initial_count - len(self.credentials)

        if removed > 0:
            self._save_credentials()
            logger.info(f"[CredentialManager] 清理了 {removed} 个无效凭据")

        return removed

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


def get_credential_host_mapping() -> Dict[str, List[str]]:
    """获取凭据-主机映射的便捷函数"""
    return get_credential_manager().get_credential_host_mapping()


def suggest_credentials_for_target(target: str, known_hosts: List[str]) -> List[Dict]:
    """为目标主机建议凭据的便捷函数"""
    return get_credential_manager().suggest_credential_reuse(target, known_hosts)


def verify_credential(host: str, username: str, service: str = "smb") -> Dict:
    """验证凭据的便捷函数"""
    cm = get_credential_manager()
    creds = cm.get_by_host(host)

    for cred in creds:
        if cred.username == username:
            return cm.verify_credential(cred, service)

    return {"valid": False, "error": "凭据不存在"}


def verify_all_credentials(service: str = "smb") -> Dict:
    """验证所有凭据的便捷函数"""
    return get_credential_manager().verify_all_credentials(service)


def register():
    """注册凭据管理器"""
    pass