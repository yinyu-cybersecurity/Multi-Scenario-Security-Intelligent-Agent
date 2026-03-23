# memory/memory_manager.py
"""
记忆管理系统

三层记忆架构：
1. 工作记忆：内存中的CTFState
2. 文件记忆：实时写入文件，防止遗忘
3. 长期记忆：RAG向量库（可选）

关键信息写入规则：
- 获得凭据 → 立即写入 credentials.json
- 发现漏洞 → 立即写入 attack_history.json
- 关键发现 → 立即写入 known_facts.md
- 每轮结束 → 更新 current_task.md
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class MemoryManager:
    """
    记忆管理器

    负责将关键信息持久化到文件，防止LLM上下文遗忘
    """

    def __init__(self, memory_dir: str = ".memory"):
        self.memory_dir = Path(memory_dir)
        self._ensure_dir()

        # 文件路径
        self.credentials_file = self.memory_dir / "credentials.json"
        self.attack_history_file = self.memory_dir / "attack_history.json"
        self.known_facts_file = self.memory_dir / "known_facts.md"
        self.current_task_file = self.memory_dir / "current_task.md"
        self.proxy_status_file = self.memory_dir / "proxy_status.json"
        self.failed_attempts_file = self.memory_dir / "failed_attempts.json"

        # 初始化文件
        self._init_files()

    def _ensure_dir(self):
        """确保记忆目录存在"""
        self.memory_dir.mkdir(parents=True, exist_ok=True)

    def _init_files(self):
        """初始化记忆文件"""
        # 初始化JSON文件为空数组
        for file_path in [self.credentials_file, self.attack_history_file,
                          self.proxy_status_file, self.failed_attempts_file]:
            if not file_path.exists():
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("[]")

        # 初始化Markdown文件
        if not self.known_facts_file.exists():
            with open(self.known_facts_file, "w", encoding="utf-8") as f:
                f.write("# 已知事实\n\n")

        if not self.current_task_file.exists():
            with open(self.current_task_file, "w", encoding="utf-8") as f:
                f.write("# 当前任务状态\n\n")

    # =========================================================================
    # 凭据管理
    # =========================================================================

    def save_credential(self, cred: Dict) -> bool:
        """
        保存凭据到文件

        Args:
            cred: 凭据字典，包含 host, port, username, password 等

        Returns:
            是否保存成功
        """
        try:
            # 添加时间戳
            cred["obtained_at"] = datetime.now().isoformat()
            cred["timestamp"] = time.time()

            # 读取现有凭据
            credentials = self._read_json(self.credentials_file)

            # 检查是否已存在相同凭据
            for existing in credentials:
                if (existing.get("host") == cred.get("host") and
                    existing.get("username") == cred.get("username")):
                    # 更新现有凭据
                    existing.update(cred)
                    self._write_json(self.credentials_file, credentials)
                    return True

            # 添加新凭据
            credentials.append(cred)
            self._write_json(self.credentials_file, credentials)

            print(f"[Memory] 已保存凭据: {cred.get('username')}@{cred.get('host')}")
            return True

        except Exception as e:
            print(f"[Memory] 保存凭据失败: {e}")
            return False

    def get_credentials(self, host: str = None, cred_type: str = None) -> List[Dict]:
        """
        获取凭据列表

        Args:
            host: 筛选特定主机
            cred_type: 筛选凭据类型 (plaintext, ntlm, ssh_key等)

        Returns:
            凭据列表
        """
        credentials = self._read_json(self.credentials_file)

        if host:
            credentials = [c for c in credentials if c.get("host") == host]

        if cred_type:
            credentials = [c for c in credentials if c.get("cred_type") == cred_type]

        return credentials

    def get_best_credential(self, host: str, service: str) -> Optional[Dict]:
        """
        智能选择最佳凭据

        优先级：domain_admin > local_admin > user
        """
        credentials = self.get_credentials(host)

        # 定义优先级
        priority = ["domain_admin", "local_admin", "user", "service_account"]

        # 定义服务适用的凭据类型
        applicable_types = {
            "smb": ["plaintext", "ntlm", "kerberos"],
            "winrm": ["plaintext", "ntlm", "kerberos"],
            "wmi": ["plaintext", "ntlm", "kerberos"],
            "rdp": ["plaintext", "ntlm"],
            "ssh": ["plaintext", "ssh_key"],
            "mysql": ["plaintext"],
            "mssql": ["plaintext"],
            "redis": ["plaintext"],
        }

        allowed_types = applicable_types.get(service, ["plaintext"])

        for cred_type in priority:
            for cred in credentials:
                if cred.get("used"):
                    continue
                if cred.get("cred_type") in allowed_types:
                    return cred

        return None

    def mark_credential_used(self, host: str, username: str):
        """标记凭据已使用"""
        credentials = self._read_json(self.credentials_file)

        for cred in credentials:
            if cred.get("host") == host and cred.get("username") == username:
                cred["used"] = True
                cred["used_at"] = datetime.now().isoformat()

        self._write_json(self.credentials_file, credentials)

    # =========================================================================
    # 攻击历史
    # =========================================================================

    def save_attack_result(self, result: Dict) -> bool:
        """
        保存攻击结果

        Args:
            result: 攻击结果字典
        """
        try:
            # 添加时间戳
            result["timestamp"] = time.time()
            result["datetime"] = datetime.now().isoformat()

            # 读取历史
            history = self._read_json(self.attack_history_file)

            # 添加记录
            history.append(result)

            # 保留最近100条
            if len(history) > 100:
                history = history[-100:]

            self._write_json(self.attack_history_file, history)
            return True

        except Exception as e:
            print(f"[Memory] 保存攻击历史失败: {e}")
            return False

    def get_recent_attacks(self, limit: int = 10) -> List[Dict]:
        """获取最近的攻击记录"""
        history = self._read_json(self.attack_history_file)
        return history[-limit:]

    def get_successful_attacks(self) -> List[Dict]:
        """获取成功的攻击记录"""
        history = self._read_json(self.attack_history_file)
        return [h for h in history if h.get("success")]

    # =========================================================================
    # 已知事实
    # =========================================================================

    def save_known_fact(self, fact_type: str, content: str, source: str = "auto"):
        """
        保存已知事实

        Args:
            fact_type: 事实类型 (credential, vulnerability, config, etc.)
            content: 事实内容
            source: 来源
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(self.known_facts_file, "a", encoding="utf-8") as f:
                f.write(f"\n## {timestamp} [{fact_type}]\n")
                f.write(f"- {content}\n")
                f.write(f"- 来源: {source}\n")

            print(f"[Memory] 已记录事实: {fact_type}")
            return True

        except Exception as e:
            print(f"[Memory] 保存事实失败: {e}")
            return False

    def get_known_facts(self) -> str:
        """获取所有已知事实"""
        try:
            with open(self.known_facts_file, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""

    def update_known_facts(self, state: Dict):
        """
        从状态更新已知事实

        自动提取关键信息写入事实文件
        """
        facts = []

        # 提取凭据信息
        credentials = self.get_credentials()
        if credentials:
            cred_summary = [f"{c['username']}@{c['host']}" for c in credentials[:5]]
            facts.append(f"已获取凭据: {', '.join(cred_summary)}")

        # 提取漏洞信息
        vuln_candidates = state.get("vuln_candidates", [])
        if vuln_candidates:
            vuln_summary = [f"{v['type']}@{v['location']}" for v in vuln_candidates[:5]]
            facts.append(f"发现漏洞: {', '.join(vuln_summary)}")

        # 提取内网主机
        internal_hosts = state.get("internal_hosts", [])
        if internal_hosts:
            host_ips = [h.get("ip") for h in internal_hosts[:10] if h.get("ip")]
            facts.append(f"发现内网主机: {', '.join(host_ips)}")

        # 提取web信息
        page_features = state.get("page_features", {})
        if page_features:
            tech_stack = page_features.get("tech_stack", [])
            if tech_stack:
                facts.append(f"技术栈: {', '.join(tech_stack)}")

        # 写入事实
        for fact in facts:
            self.save_known_fact("auto", fact)

    # =========================================================================
    # 当前任务状态
    # =========================================================================

    def update_current_task(self, state: Dict):
        """
        更新当前任务状态

        Args:
            state: CTFState状态字典
        """
        try:
            content = f"""# 当前任务状态

## 基本信息
- 任务名称: {state.get('task_name', 'Unknown')}
- 目标URL: {state.get('target_url', 'Unknown')}
- 当前URL: {state.get('current_url', 'Unknown')}
- 当前模式: {state.get('current_mode', 'exploit')}

## 执行进度
- 执行步数: {state.get('execution_steps', 0)}
- 当前轮次: {state.get('current_round', 0)}
- 失败分数: {state.get('failure_weighted_score', 0):.2f}

## 发现概览
- 已访问URL: {len(state.get('visited_urls', []))} 个
- 漏洞候选: {len(state.get('vuln_candidates', []))} 个
- 获取凭据: {len(self.get_credentials())} 个
- 内网主机: {len(state.get('internal_hosts', []))} 台

## 模式状态
- Web模式: {not any([state.get('pwn_mode'), state.get('reverse_mode'), state.get('crypto_mode'), state.get('misc_mode'), state.get('internal_mode')])}
- Pwn模式: {state.get('pwn_mode', False)}
- Reverse模式: {state.get('reverse_mode', False)}
- Crypto模式: {state.get('crypto_mode', False)}
- Misc模式: {state.get('misc_mode', False)}
- 内网模式: {state.get('internal_mode', False)}

## 最近攻击
"""
            # 添加最近攻击
            recent_attacks = self.get_recent_attacks(5)
            for attack in recent_attacks:
                status = "✓" if attack.get("success") else "✗"
                content += f"- {status} {attack.get('tool', 'unknown')}: {attack.get('target', 'unknown')}\n"

            content += f"""
## 已知事实摘要
{self.get_known_facts()[-1000:] if self.get_known_facts() else '暂无'}

---
更新时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

            with open(self.current_task_file, "w", encoding="utf-8") as f:
                f.write(content)

        except Exception as e:
            print(f"[Memory] 更新任务状态失败: {e}")

    def get_current_task_summary(self) -> str:
        """获取当前任务摘要"""
        try:
            with open(self.current_task_file, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""

    # =========================================================================
    # 代理状态
    # =========================================================================

    def save_proxy_status(self, proxy_info: Dict):
        """保存代理状态"""
        try:
            proxy_info["updated_at"] = datetime.now().isoformat()

            proxies = self._read_json(self.proxy_status_file)
            proxies.append(proxy_info)

            self._write_json(self.proxy_status_file, proxies)
            return True
        except Exception as e:
            print(f"[Memory] 保存代理状态失败: {e}")
            return False

    def get_active_proxies(self) -> List[Dict]:
        """获取活跃的代理"""
        proxies = self._read_json(self.proxy_status_file)
        return [p for p in proxies if p.get("status") == "active"]

    # =========================================================================
    # 失败尝试
    # =========================================================================

    def save_failed_attempt(self, attempt: Dict):
        """保存失败的尝试，避免重复"""
        try:
            attempt["timestamp"] = time.time()

            attempts = self._read_json(self.failed_attempts_file)

            # 检查是否已存在类似失败
            key = f"{attempt.get('tool')}:{attempt.get('target')}:{attempt.get('payload', '')}"

            for existing in attempts:
                existing_key = f"{existing.get('tool')}:{existing.get('target')}:{existing.get('payload', '')}"
                if existing_key == key:
                    return  # 已存在，不重复记录

            attempts.append(attempt)

            # 保留最近50条
            if len(attempts) > 50:
                attempts = attempts[-50:]

            self._write_json(self.failed_attempts_file, attempts)

        except Exception as e:
            print(f"[Memory] 保存失败尝试失败: {e}")

    def is_failed_before(self, tool: str, target: str, payload: str = "") -> bool:
        """检查是否已失败过"""
        attempts = self._read_json(self.failed_attempts_file)

        for attempt in attempts:
            if (attempt.get("tool") == tool and
                attempt.get("target") == target and
                attempt.get("payload", "") == payload):
                return True

        return False

    # =========================================================================
    # 工具方法
    # =========================================================================

    def _read_json(self, file_path: Path) -> List:
        """读取JSON文件"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write_json(self, file_path: Path, data: List):
        """写入JSON文件"""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def compress_memory(self):
        """压缩旧记忆，防止文件过大"""
        # 压缩攻击历史
        history = self._read_json(self.attack_history_file)
        if len(history) > 100:
            # 保留成功记录和最近50条
            successful = [h for h in history if h.get("success")]
            recent = history[-50:]
            combined = successful + recent
            # 去重
            seen = set()
            unique = []
            for h in combined:
                key = h.get("timestamp")
                if key not in seen:
                    seen.add(key)
                    unique.append(h)
            self._write_json(self.attack_history_file, unique)

        # 压缩凭据（去重）
        credentials = self._read_json(self.credentials_file)
        seen = set()
        unique_creds = []
        for c in credentials:
            key = f"{c.get('host')}:{c.get('username')}"
            if key not in seen:
                seen.add(key)
                unique_creds.append(c)
        self._write_json(self.credentials_file, unique_creds)

    def export_session(self) -> Dict:
        """导出整个会话记录"""
        return {
            "credentials": self.get_credentials(),
            "attack_history": self.get_recent_attacks(100),
            "known_facts": self.get_known_facts(),
            "proxies": self.get_active_proxies(),
            "exported_at": datetime.now().isoformat()
        }

    def clear_memory(self):
        """清空所有记忆（谨慎使用）"""
        self._init_files()
        print("[Memory] 所有记忆已清空")


# 全局记忆管理器实例
_memory_manager = None


def get_memory_manager() -> MemoryManager:
    """获取全局记忆管理器实例"""
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = MemoryManager()
    return _memory_manager


# 便捷函数
def save_credential(host: str, username: str, password: str = None,
                    port: int = None, cred_type: str = "plaintext",
                    domain: str = None, **kwargs):
    """保存凭据便捷函数"""
    cred = {
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "cred_type": cred_type,
        "domain": domain,
        **kwargs
    }
    return get_memory_manager().save_credential(cred)


def save_attack(tool: str, target: str, success: bool,
                response: str = "", **kwargs):
    """保存攻击记录便捷函数"""
    result = {
        "tool": tool,
        "target": target,
        "success": success,
        "response": response[:500] if response else "",
        **kwargs
    }
    return get_memory_manager().save_attack_result(result)


def save_fact(content: str, fact_type: str = "discovery"):
    """保存事实便捷函数"""
    return get_memory_manager().save_known_fact(fact_type, content)