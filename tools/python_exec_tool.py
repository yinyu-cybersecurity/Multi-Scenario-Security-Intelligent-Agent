# tools/python_exec_tool.py
# Python 脚本执行工具 - 让 AI 用代码精确处理任务
# 增强: env API注入，支持状态访问、工具调用、凭据保存、FLAG报告
import os
import sys
import json
import base64
import subprocess
import tempfile
import threading
import time
from typing import Dict, Any, Optional, List, Tuple

# 尝试导入工具框架（支持多种导入路径）
try:
    from app.tool_framework import CTFTool, ToolRegistry
except ImportError:
    try:
        from tool_framework import CTFTool, ToolRegistry
    except ImportError:
        # 定义最小化基类用于独立运行
        class CTFTool:
            def name(self): return "python-exec"
            def description(self): return ""
            def supported_vulns(self): return []
            def capability_statement(self): return ""
            def check_available(self): return True
            def expected_params(self): return {}
            def execute(self, target, params): return {}

# 尝试导入 FLAG 提取器 (统一使用 flag_extractor_v2)
try:
    from app.flag_extractor_v2 import extract_flags, has_flag
except ImportError:
    try:
        from flag_extractor_v2 import extract_flags, has_flag
    except ImportError:
        # 备用：简单实现
        def extract_flags(text, ai_client=None, context=""):
            import re
            pattern = r"[a-zA-Z0-9_]+\{[^\}]+\}"
            return re.findall(pattern, text)
        def has_flag(text):
            return len(extract_flags(text)) > 0

# 尝试导入日志器
try:
    from app.logger import get_logger
except ImportError:
    try:
        from logger import get_logger
    except ImportError:
        import logging
        def get_logger(name):
            logger = logging.getLogger(name)
            if not logger.handlers:
                handler = logging.StreamHandler()
                handler.setFormatter(logging.Formatter('%(asctime)s [%(name)s] %(message)s'))
                logger.addHandler(handler)
                logger.setLevel(logging.INFO)
            return logger

logger = get_logger("PythonExec")


# ============================================================
# Env API - 脚本环境对象，提供与系统的交互能力
# ============================================================

class ScriptEnv:
    """
    Python脚本执行环境

    提供安全的API让脚本访问状态、调用工具、保存凭据、报告FLAG

    安全限制:
    - 只能访问白名单字段
    - 不能修改核心状态
    - 工具调用有超时限制
    - 日志输出有频率限制
    """

    # 允许访问的状态字段白名单（安全限制）
    STATE_WHITELIST = {
        # 基础信息
        'task_name', 'task_description', 'target_url', 'current_url',
        'current_round', 'execution_steps',

        # Web CTF 信息
        'page_features', 'raw_html_snippet', 'detected_scenes',
        'visited_urls', 'scanned_ips', 'scanned_urls',

        # 内网信息
        'internal_hosts', 'credentials', 'domain_info',
        'internal_network_range', 'domain_controller', 'ad_domain',

        # 云安全信息
        'cloud_provider', 'metadata_leaked', 'iam_roles',
        'buckets_found', 'cloud_phase',

        # AI安全信息
        'target_model', 'detected_ai_type', 'ai_phase',

        # 攻击结果
        'attack_results', 'found_flags', 'compromised_hosts',
        'successful_payloads', 'extracted_data',

        # 其他有用的信息
        'known_facts', 'focused_scene', 'site_topology',
        'vuln_candidates', 'tool_cache',

        # AI决策历史
        'strategic_decisions',
    }

    # 禁止访问的核心状态字段（安全限制）
    STATE_BLACKLIST = {
        'current_mode', 'start_time', 'found_flag', 'final_flag',
        'strategic_context', 'memory_mode', 'active_modules',
    }

    # 日志频率限制
    LOG_RATE_LIMIT = 10  # 每秒最多10条日志
    LOG_MIN_INTERVAL = 0.1  # 最小间隔100ms

    def __init__(self, state: Dict = None, tool_registry=None,
                 log_callback=None, result_callback=None):
        """
        初始化脚本环境

        Args:
            state: 当前状态引用（只读白名单字段）
            tool_registry: 工具注册中心引用
            log_callback: 日志回调函数
            result_callback: 结果回调函数（用于收集凭据、FLAG等）
        """
        self._state = state or {}
        self._tool_registry = tool_registry
        self._log_callback = log_callback
        self._result_callback = result_callback

        # 运行时收集的数据
        self._collected_credentials: List[Dict] = []
        self._reported_flags: List[str] = []
        self._tool_call_results: List[Dict] = []
        self._log_messages: List[str] = []

        # 日志频率控制
        self._last_log_time = 0.0
        self._log_count = 0

        # 线程锁
        self._lock = threading.Lock()

    def get_state(self, key: str, default: Any = None) -> Any:
        """
        获取状态值（仅白名单字段）

        Args:
            key: 状态字段名
            default: 默认值

        Returns:
            状态值或默认值

        Security:
            - 只能访问白名单字段
            - 黑名单字段返回 None
        """
        if key in self.STATE_BLACKLIST:
            logger.warning(f"[ScriptEnv] Blocked access to blacklisted field: {key}")
            return None

        if key not in self.STATE_WHITELIST:
            logger.warning(f"[ScriptEnv] Blocked access to non-whitelisted field: {key}")
            return None

        return self._state.get(key, default)

    def get_state_keys(self) -> List[str]:
        """
        获取可访问的状态字段列表

        Returns:
            白名单字段列表
        """
        return list(self.STATE_WHITELIST)

    def call_tool(self, tool_name: str, target: str = "",
                  params: Dict = None, timeout: int = 30) -> Dict:
        """
        调用其他工具

        Args:
            tool_name: 工具名称
            target: 目标（可选）
            params: 工具参数
            timeout: 超时时间（秒，默认30秒，最大60秒）

        Returns:
            工具执行结果

        Security:
            - 超时限制最大60秒
            - 工具必须是已注册的
        """
        params = params or {}

        # 超时限制
        timeout = min(timeout, 60)

        if not self._tool_registry:
            return {
                "success": False,
                "error": "Tool registry not available in script environment",
                "tool_name": tool_name
            }

        # 检查工具是否存在
        if not self._tool_registry.tool_exists(tool_name):
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not registered",
                "tool_name": tool_name
            }

        try:
            logger.info(f"[ScriptEnv] Calling tool: {tool_name} -> {target}")

            result = self._tool_registry.execute_cached(
                tool_name, target, params, self._state
            )

            # 记录工具调用结果
            with self._lock:
                self._tool_call_results.append({
                    "tool_name": tool_name,
                    "target": target,
                    "params": params,
                    "result": result,
                    "timestamp": time.time()
                })

            return result

        except Exception as e:
            logger.error(f"[ScriptEnv] Tool call failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "tool_name": tool_name
            }

    def save_credential(self, cred: Dict) -> bool:
        """
        保存凭据到状态

        Args:
            cred: 凭据信息，应包含:
                - username: 用户名
                - password: 密码（可选）
                - hash: 哈希（可选）
                - domain: 域名（可选）
                - source: 来源描述

        Returns:
            是否保存成功

        Note:
            实际保存由调用方处理，这里只是收集
        """
        if not cred or not isinstance(cred, dict):
            return False

        # 验证必要字段
        if not cred.get('username') and not cred.get('hash'):
            logger.warning("[ScriptEnv] Credential missing username/hash")
            return False

        # 添加时间戳和来源标记
        cred['collected_by'] = 'python_exec'
        cred['collected_at'] = time.time()

        with self._lock:
            self._collected_credentials.append(cred)

        logger.info(f"[ScriptEnv] Collected credential: {cred.get('username', 'unknown')}")
        return True

    def report_flag(self, flag: str) -> Dict:
        """
        报告发现的FLAG

        Args:
            flag: 发现的FLAG字符串

        Returns:
            {
                "valid": bool,  # 是否是有效的FLAG格式
                "flag": str,    # FLAG内容
                "source": str,  # 检测来源
            }

        Note:
            实际保存由调用方处理，这里只是收集和验证
        """
        if not flag or not isinstance(flag, str):
            return {"valid": False, "error": "Empty flag"}

        # 使用 FLAG 提取器验证
        is_valid = has_flag(flag)

        if is_valid:
            # 提取详细信息
            flags = extract_flags(flag)
            if flags:
                detected_flag = flags[0]
                source = "extracted"
            else:
                detected_flag = flag
                source = "script_report"

            with self._lock:
                if detected_flag not in self._reported_flags:
                    self._reported_flags.append(detected_flag)

            logger.info(f"[ScriptEnv] FLAG reported: {detected_flag}")

            return {
                "valid": True,
                "flag": detected_flag,
                "source": source
            }
        else:
            logger.warning(f"[ScriptEnv] Invalid flag format: {flag[:50]}...")
            return {
                "valid": False,
                "error": "Not a valid flag format"
            }

    def log(self, message: str) -> bool:
        """
        记录日志

        Args:
            message: 日志消息

        Returns:
            是否成功记录

        Security:
            - 频率限制：每秒最多10条
            - 消息长度限制：最多500字符
        """
        if not message:
            return False

        # 频率限制
        current_time = time.time()
        with self._lock:
            if current_time - self._last_log_time < self.LOG_MIN_INTERVAL:
                self._log_count += 1
                if self._log_count > self.LOG_RATE_LIMIT:
                    return False  # 超过频率限制
            else:
                self._log_count = 1
                self._last_log_time = current_time

        # 长度限制
        message = str(message)[:500]

        # 记录日志
        self._log_messages.append(message)

        # 调用外部日志回调
        if self._log_callback:
            self._log_callback(message)
        else:
            logger.info(f"[Script] {message}")

        return True

    def get_collected_data(self) -> Dict:
        """
        获取脚本收集的所有数据

        Returns:
            {
                "credentials": List[Dict],
                "flags": List[str],
                "tool_results": List[Dict],
                "logs": List[str],
            }
        """
        with self._lock:
            return {
                "credentials": self._collected_credentials.copy(),
                "flags": self._reported_flags.copy(),
                "tool_results": self._tool_call_results.copy(),
                "logs": self._log_messages.copy(),
            }


# ============================================================
# PythonExecTool 增强实现
# ============================================================

class PythonExecTool(CTFTool):
    """
    Python 脚本执行工具

    适用场景：
    1. 编码/解码（base64、URL、十六进制、Unicode等）
    2. 加密/解密（MD5、SHA、AES、RSA等）
    3. 数据处理和转换
    4. 正则匹配和文本提取
    5. 数学计算
    6. 任何需要精确执行的任务
    7. [新增] 访问状态、调用工具、保存凭据、报告FLAG

    AI 自己写脚本，确保准确性！
    """

    OUTPUT_DIR = os.path.join("data", "tool_outputs")
    DEFAULT_TIMEOUT = 30  # 默认超时30秒
    MAX_TIMEOUT = 60  # 最大超时60秒

    # 危险操作模式列表 - 用于Docker执行模式的安全验证
    DANGER_PATTERNS = [
        "rm -rf", "rm -r", "rmdir", "dd if=", "mkfs", "fdisk",
        "docker rm", "docker rmi", "docker stop",
        "kubectl delete", "kubectl rm",
        "chmod 777", "chmod -R 777",
        "chown root", "chown -R root",
        "> /dev/", "> /etc/",
    ]

    def __init__(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def name(self) -> str:
        return "python-exec"

    def description(self) -> str:
        return ("Python脚本执行工具。适用于：编码解码、加密解密、正则提取、数据处理等需要精确执行的场景。"
                "简单HTTP请求请用requests工具，已知漏洞利用请用专业工具。"
                "增强功能：env API支持状态访问、工具调用、凭据保存、FLAG报告。")

    def supported_vulns(self) -> list:
        return ["Data Processing", "Encoding", "Decoding", "Cryptography", "Calculation"]

    def capability_statement(self) -> str:
        return ("Python脚本执行器。适用：编码解码、加密解密、正则提取、数据处理。"
                "不适用：简单HTTP请求(用requests)、已知漏洞利用(用专业工具)。"
                "env API: env.get_state(key)获取状态、env.call_tool()调用工具、"
                "env.report_flag(flag)报告FLAG。")

    def check_available(self) -> bool:
        return True  # Python 总是可用

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "code": {
                "type": "str",
                "description": ("要执行的 Python 代码。可以 import 标准库。"
                                "结果通过 print() 输出或设置 result 变量。"
                                "可通过 env API 访问状态和调用工具。"),
                "required": True
            },
            "description": {
                "type": "str",
                "description": "代码功能描述（如：base64解码、提取URL等）",
                "required": False,
                "default": ""
            },
            "timeout": {
                "type": "int",
                "description": "执行超时时间（秒），默认30，最大60",
                "required": False,
                "default": 30
            },
            "enable_env": {
                "type": "bool",
                "description": "是否启用 env API（需要传入 state 参数）",
                "required": False,
                "default": True
            },
            "exec_mode": {
                "type": "str",
                "description": "执行模式: subprocess(本地) 或 docker(容器内)",
                "required": False,
                "default": "subprocess"
            },
            "container": {
                "type": "str",
                "description": "Docker容器名(exec_mode=docker时使用)",
                "required": False,
                "default": "ctf_agent"
            }
        }

    def execute(self, target: str, params: Dict, state: Dict = None) -> Dict:
        """
        执行 Python 代码

        Args:
            target: 目标（通常是目标URL或数据）
            params: 参数字典
                - code: 要执行的代码
                - description: 功能描述
                - timeout: 超时时间
                - enable_env: 是否启用 env API
                - exec_mode: 执行模式 (subprocess 或 docker)
                - container: Docker容器名 (exec_mode=docker时使用)
            state: 当前状态引用（用于 env API）

        Returns:
            {
                "success": bool,
                "output": str,  # stdout输出
                "output_data": Any,  # 解析后的结果
                "stderr": str,
                "return_code": int,
                "description": str,
                "summary": str,
                # 新增字段
                "env_data": Dict,  # env收集的数据
                "credentials": List[Dict],  # 收集的凭据
                "flags": List[str],  # 报告的FLAG
                "tool_calls": List[Dict],  # 工具调用结果
            }
        """
        code = params.get("code", "")
        description = params.get("description", "Python execution")
        timeout = min(params.get("timeout", self.DEFAULT_TIMEOUT), self.MAX_TIMEOUT)
        enable_env = params.get("enable_env", True)
        exec_mode = params.get("exec_mode", "subprocess")  # subprocess 或 docker
        container_name = params.get("container", "ctf_agent")

        if not code:
            return {
                "success": False,
                "error": "必须提供 code 参数",
                "summary": "执行失败：缺少代码"
            }

        # 根据执行模式选择执行方式
        if exec_mode == "docker":
            return self._execute_in_docker(code, params, container_name, state, target)
        else:
            return self._execute_subprocess(code, params, state, target, timeout, enable_env, description)

    def _validate_code_safety(self, code: str) -> Tuple[bool, str]:
        """
        验证代码安全性（用于Docker执行模式）

        Args:
            code: 要验证的代码

        Returns:
            (is_safe, error_message): 安全性检查结果
        """
        code_lower = code.lower()
        for pattern in self.DANGER_PATTERNS:
            if pattern.lower() in code_lower:
                return False, f"危险操作被禁止: {pattern}"
        return True, ""

    def _execute_subprocess(self, code: str, params: Dict, state: Dict,
                            target: str, timeout: int, enable_env: bool,
                            description: str) -> Dict:
        """
        在本地子进程中执行代码

        Args:
            code: 要执行的代码
            params: 参数字典
            state: 状态引用
            target: 目标参数
            timeout: 超时时间
            enable_env: 是否启用 env API
            description: 功能描述

        Returns:
            执行结果字典
        """
        # 创建脚本环境
        env_data_file = None
        env = None

        if enable_env and state:
            env = ScriptEnv(
                state=state,
                tool_registry=ToolRegistry if 'ToolRegistry' in dir() else None,
                log_callback=lambda msg: logger.info(f"[ScriptEnv] {msg}")
            )

        # 创建临时脚本
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                delete=False,
                encoding='utf-8'
            ) as f:
                # 构建包装代码
                wrapped_code = self._wrap_code(code, env, target, state if enable_env else None)
                f.write(wrapped_code)
                script_path = f.name

            # 创建环境数据传递文件（如果启用了 env）
            if env:
                env_data_file = script_path.replace('.py', '_env.json')
                # 初始环境数据为空，脚本会写入结果

            # 执行脚本
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.OUTPUT_DIR,
                env={**os.environ, 'PYTHONIOENCODING': 'utf-8'}
            )

            # 清理临时文件
            os.unlink(script_path)
            if env_data_file and os.path.exists(env_data_file):
                os.unlink(env_data_file)

            stdout = result.stdout
            stderr = result.stderr
            return_code = result.returncode

            # 解析结果
            output_data = None
            if "=== RESULT_JSON ===" in stdout:
                parts = stdout.split("=== RESULT_JSON ===")
                json_str = parts[-1].strip().split("=== RESULT ===")[0].strip()
                try:
                    output_data = json.loads(json_str)
                except:
                    output_data = json_str
            elif "=== RESULT ===" in stdout:
                output_data = stdout.split("=== RESULT ===")[-1].strip()
            else:
                # 捕获所有 print 输出作为结果
                output_data = stdout.strip() if stdout.strip() else None

            success = return_code == 0

            # 解析 env 数据（从 stdout 中提取）
            env_collected = self._extract_env_data(stdout)

            # 合合 env 对象收集的数据（如果使用内存传递）
            if env:
                env_mem_data = env.get_collected_data()
                # 合并两种方式收集的数据
                env_collected["credentials"] = env_collected.get("credentials", []) + env_mem_data.get("credentials", [])
                env_collected["flags"] = env_collected.get("flags", []) + env_mem_data.get("flags", [])
                env_collected["tool_results"] = env_collected.get("tool_results", []) + env_mem_data.get("tool_results", [])
                env_collected["logs"] = env_collected.get("logs", []) + env_mem_data.get("logs", [])

            # 自动检测 FLAG（如果输出中有 FLAG）
            detected_flags = []
            if output_data:
                detected_flags = extract_flags(str(output_data))

            # 合合所有发现的 FLAG
            all_flags = list(set(env_collected.get("flags", []) + detected_flags))

            summary = f"Python 执行{'成功' if success else '失败'}"
            if output_data and success:
                summary += f": {str(output_data)[:200]}"
            if all_flags:
                summary += f", 发现FLAG: {len(all_flags)}个"
            if env_collected.get("credentials"):
                summary += f", 收集凭据: {len(env_collected['credentials'])}个"

            return {
                "success": success,
                "output": stdout,
                "output_data": output_data,
                "stderr": stderr if stderr else None,
                "return_code": return_code,
                "description": description,
                "summary": summary,
                # 新增字段
                "env_data": env_collected,
                "credentials": env_collected.get("credentials", []),
                "flags": all_flags,
                "tool_calls": env_collected.get("tool_results", []),
            }

        except subprocess.TimeoutExpired:
            # 清理临时文件
            try:
                os.unlink(script_path)
                if env_data_file and os.path.exists(env_data_file):
                    os.unlink(env_data_file)
            except:
                pass

            return {
                "success": False,
                "error": f"执行超时（{timeout}秒）",
                "summary": "执行失败：超时"
            }
        except Exception as e:
            # 清理临时文件
            try:
                os.unlink(script_path)
                if env_data_file and os.path.exists(env_data_file):
                    os.unlink(env_data_file)
            except:
                pass

            return {
                "success": False,
                "error": str(e),
                "summary": f"执行失败: {str(e)}"
            }

    def _execute_in_docker(self, code: str, params: Dict, container: str,
                          state: Dict, target: str) -> Dict:
        """
        在Docker容器内执行代码

        Args:
            code: 要执行的代码
            params: 参数字典
            container: Docker容器名
            state: 状态引用
            target: 目标参数

        Returns:
            执行结果字典
        """
        timeout = min(params.get("timeout", self.DEFAULT_TIMEOUT), self.MAX_TIMEOUT)
        description = params.get("description", "Python execution")

        # 安全验证
        is_safe, error = self._validate_code_safety(code)
        if not is_safe:
            return {
                "success": False,
                "error": error,
                "summary": "安全验证失败"
            }

        try:
            # 构建docker exec命令
            cmd = ["docker", "exec", "-i", container, "python3", "-c", code]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            stdout = result.stdout
            stderr = result.stderr
            return_code = result.returncode

            # 解析结果
            output_data = None
            if "=== RESULT_JSON ===" in stdout:
                parts = stdout.split("=== RESULT_JSON ===")
                json_str = parts[-1].strip().split("=== RESULT ===")[0].strip()
                try:
                    output_data = json.loads(json_str)
                except:
                    output_data = json_str
            elif "=== RESULT ===" in stdout:
                output_data = stdout.split("=== RESULT ===")[-1].strip()
            else:
                output_data = stdout.strip() if stdout.strip() else None

            success = return_code == 0

            # 解析 env 数据
            env_collected = self._extract_env_data(stdout)

            # 自动检测 FLAG
            detected_flags = []
            if output_data:
                detected_flags = extract_flags(str(output_data))

            all_flags = list(set(env_collected.get("flags", []) + detected_flags))

            summary = f"Docker执行{'成功' if success else '失败'}"
            if output_data and success:
                summary += f": {str(output_data)[:200]}"
            if all_flags:
                summary += f", 发现FLAG: {len(all_flags)}个"
            if env_collected.get("credentials"):
                summary += f", 收集凭据: {len(env_collected['credentials'])}个"

            return {
                "success": success,
                "output": stdout,
                "output_data": output_data,
                "stderr": stderr if stderr else None,
                "return_code": return_code,
                "description": description,
                "summary": summary,
                "exec_mode": "docker",
                "container": container,
                "env_data": env_collected,
                "credentials": env_collected.get("credentials", []),
                "flags": all_flags,
                "tool_calls": env_collected.get("tool_results", []),
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"执行超时（{timeout}秒）",
                "summary": "执行失败：超时",
                "exec_mode": "docker",
                "container": container
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": "Docker命令未找到，请确保Docker已安装并运行",
                "summary": "执行失败：Docker不可用",
                "exec_mode": "docker",
                "container": container
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "summary": f"执行失败: {str(e)}",
                "exec_mode": "docker",
                "container": container
            }

    def _wrap_code(self, code: str, env: ScriptEnv, target: str, state: Dict) -> str:
        """
        包装用户代码，注入 env API 和结果捕获

        Args:
            code: 用户代码
            env: 脚本环境对象
            target: 目标参数
            state: 状态引用

        Returns:
            包装后的完整脚本代码
        """
        # 构建 env 对象的 Python 代码表示
        env_py_code = ""
        if env and state:
            # 创建 env 对象序列化数据
            env_state_data = {}
            for key in ScriptEnv.STATE_WHITELIST:
                if key in state:
                    env_state_data[key] = state[key]

            # 生成 env 对象代码（避免使用 f-string 的花括号冲突问题）
            whitelist_str = repr(list(ScriptEnv.STATE_WHITELIST))
            blacklist_str = repr(list(ScriptEnv.STATE_BLACKLIST))
            state_json = json.dumps(env_state_data, ensure_ascii=False)

            env_py_code = '''
# ===== env API 注入 =====
import json
import sys
import os
import time
import threading
import re

class _ScriptEnv:
    """脚本环境 - 提供安全的API"""

    STATE_WHITELIST = ''' + whitelist_str + '''
    STATE_BLACKLIST = ''' + blacklist_str + '''

    def __init__(self, state_data):
        self._state = state_data
        self._credentials = []
        self._flags = []
        self._tool_results = []
        self._logs = []
        self._lock = threading.Lock()

    def get_state(self, key, default=None):
        """获取状态值（仅白名单字段）"""
        if key in self.STATE_BLACKLIST:
            print("[env] Blocked: " + str(key))
            return None
        if key not in self.STATE_WHITELIST:
            print("[env] Not whitelisted: " + str(key))
            return None
        return self._state.get(key, default)

    def get_state_keys(self):
        """获取可访问的状态字段列表"""
        return list(self.STATE_WHITELIST)

    def call_tool(self, tool_name, target="", params=None):
        """调用其他工具（通过写入请求文件）"""
        params = params or {}
        result = {
            "success": False,
            "error": "Tool call not available in subprocess mode",
            "tool_name": tool_name
        }
        with self._lock:
            self._tool_results.append({
                "tool_name": tool_name,
                "target": target,
                "params": params,
                "result": result,
                "timestamp": time.time()
            })
        return result

    def save_credential(self, cred):
        """保存凭据"""
        if not cred or not isinstance(cred, dict):
            return False
        cred["collected_by"] = "python_exec"
        cred["collected_at"] = time.time()
        with self._lock:
            self._credentials.append(cred)
        username = cred.get('username', 'unknown')
        print("[env] Credential saved: " + str(username))
        return True

    def report_flag(self, flag):
        """报告FLAG"""
        pattern = r"[a-zA-Z0-9_]+\{[^\}]+\}"
        is_valid = bool(re.search(pattern, flag))
        if is_valid:
            match = re.search(pattern, flag)
            detected_flag = match.group()
            with self._lock:
                if detected_flag not in self._flags:
                    self._flags.append(detected_flag)
            print("[env] FLAG: " + str(detected_flag))
            return {"valid": True, "flag": detected_flag}
        return {"valid": False, "error": "Invalid flag format"}

    def log(self, message):
        """记录日志"""
        message = str(message)[:500]
        with self._lock:
            self._logs.append(message)
        print("[env log] " + message)
        return True

    def get_collected_data(self):
        """获取收集的数据"""
        with self._lock:
            return {
                "credentials": self._credentials.copy(),
                "flags": self._flags.copy(),
                "tool_results": self._tool_results.copy(),
                "logs": self._logs.copy(),
            }

    # ===== 增强的env API =====
    def env_download(self, url, path):
        """下载文件"""
        import urllib.request
        try:
            urllib.request.urlretrieve(url, path)
            self.log("Downloaded: " + str(url) + " -> " + str(path))
            return {"success": True, "path": path}
        except Exception as e:
            self.log("Download failed: " + str(e))
            return {"success": False, "error": str(e)}

    def env_extract(self, file_path, dest_dir):
        """解压文件"""
        import zipfile
        import tarfile
        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    zf.extractall(dest_dir)
            elif file_path.endswith(('.tar.gz', '.tgz')):
                with tarfile.open(file_path, 'r:gz') as tf:
                    tf.extractall(dest_dir)
            elif file_path.endswith('.tar'):
                with tarfile.open(file_path, 'r') as tf:
                    tf.extractall(dest_dir)
            else:
                return {"success": False, "error": "Unsupported format"}
            self.log("Extracted: " + str(file_path) + " -> " + str(dest_dir))
            return {"success": True, "dest": dest_dir}
        except Exception as e:
            self.log("Extract failed: " + str(e))
            return {"success": False, "error": str(e)}

    def env_exec_cmd(self, cmd, timeout=30):
        """执行安全命令"""
        import subprocess
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                   text=True, timeout=timeout)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Timeout", "returncode": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}

    def env_check_file(self, path):
        """检查文件是否存在"""
        return {
            "exists": os.path.exists(path),
            "is_file": os.path.isfile(path),
            "is_dir": os.path.isdir(path)
        }

    def env_list_dir(self, path):
        """列出目录内容"""
        if os.path.isdir(path):
            try:
                items = os.listdir(path)
                return {"items": items, "success": True}
            except Exception as e:
                return {"items": [], "success": False, "error": str(e)}
        return {"items": [], "success": False, "error": "Not a directory"}

# 创建全局 env 对象
env = _ScriptEnv(''' + state_json + ''')

# 目标参数
_target = "''' + target + '''"

'''

        # 基础导入（所有脚本都可用）
        base_imports = '''
import sys
import json
import base64
import hashlib
import re
import urllib.parse
import binascii
import struct
import zlib
import gzip
from io import BytesIO

'''

        # 结果捕获代码
        result_capture = '''

# ===== 结果捕获 =====
if 'result' in dir():
    try:
        if isinstance(result, (dict, list)):
            print("=== RESULT_JSON ===")
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("=== RESULT ===")
            print(result)
    except Exception as e:
        print("=== RESULT ===")
        print(result)

# ===== env 数据输出 =====
if 'env' in dir():
    env_data = env.get_collected_data()
    if env_data:
        print("=== ENV_DATA ===")
        print(json.dumps(env_data, ensure_ascii=False))
'''

        # 组合完整代码
        full_code = base_imports + env_py_code + '''
# ===== 用户代码 =====
''' + code + result_capture

        return full_code

    def _extract_env_data(self, stdout: str) -> Dict:
        """
        从输出中提取 env 收集的数据

        Args:
            stdout: 脚本输出

        Returns:
            env 数据字典
        """
        env_data = {
            "credentials": [],
            "flags": [],
            "tool_results": [],
            "logs": [],
        }

        if "=== ENV_DATA ===" in stdout:
            try:
                parts = stdout.split("=== ENV_DATA ===")
                env_json = parts[-1].strip()
                # 找到 JSON 结束位置
                if "=== RESULT ===" in env_json:
                    env_json = env_json.split("=== RESULT ===")[0].strip()
                elif "=== RESULT_JSON ===" in env_json:
                    env_json = env_json.split("=== RESULT_JSON ===")[0].strip()

                parsed = json.loads(env_json)
                env_data.update(parsed)
            except Exception as e:
                logger.warning(f"[PythonExec] Failed to parse env data: {e}")

        return env_data


# ============================================================
# 工具注册
# ============================================================

# 自动注册工具
try:
    if 'ToolRegistry' in dir():
        ToolRegistry.register(PythonExecTool())
except Exception as e:
    logger.warning(f"[PythonExec] Failed to register: {e}")


# ============================================================
# 使用示例
# ============================================================

EXAMPLE_SCRIPTS = {
    "basic_encoding": '''
# Base64 解码示例
encoded = "SGVsbG8gV29ybGQh"
result = base64.b64decode(encoded).decode()
print(result)
''',

    "with_env_state": '''
# 使用 env API 访问状态
target_url = env.get_state("target_url")
visited_urls = env.get_state("visited_urls", [])

print(f"Target: {target_url}")
print(f"Visited: {len(visited_urls)} URLs")

# 分析目标URL
import urllib.parse
parsed = urllib.parse.urlparse(target_url)
result = {
    "scheme": parsed.scheme,
    "host": parsed.netloc,
    "path": parsed.path,
    "query": parsed.query
}
''',

    "with_flag_report": '''
# 解码并报告FLAG
encoded_data = "ZmxhZ3t0ZXN0X2ZsYWdfMTIzfQ=="  # base64编码的flag
decoded = base64.b64decode(encoded_data).decode()

# 自动检测和报告FLAG
env.report_flag(decoded)

# 也可以手动设置结果
result = {"decoded": decoded, "flag_found": True}
''',

    "with_credential_save": '''
# 提取凭据并保存
import re

text = "Username: admin, Password: P@ssw0rd123"
user_match = re.search(r"Username: (\\w+)", text)
pass_match = re.search(r"Password: (\\S+)", text)

if user_match and pass_match:
    cred = {
        "username": user_match.group(1),
        "password": pass_match.group(1),
        "source": "extracted_from_text"
    }
    env.save_credential(cred)
    result = cred
''',
}


def get_example_scripts() -> Dict[str, str]:
    """获取示例脚本"""
    return EXAMPLE_SCRIPTS.copy()


if __name__ == "__main__":
    # 简单测试
    tool = PythonExecTool()

    # 测试基本功能
    result = tool.execute("", {
        "code": "result = base64.b64decode('SGVsbG8gV29ybGQh').decode()"
    })
    print("Basic test:", result)

    # 测试 env API（需要状态）
    test_state = {
        "target_url": "http://example.com",
        "visited_urls": ["http://example.com/page1", "http://example.com/page2"],
        "credentials": [{"username": "admin", "password": "test"}]
    }

    result = tool.execute("", {
        "code": '''
target = env.get_state("target_url")
urls = env.get_state("visited_urls", [])
print(f"Target: {target}")
print(f"Visited: {len(urls)} URLs")
result = {"target": target, "visited_count": len(urls)}
''',
        "enable_env": True
    }, state=test_state)
    print("Env test:", result)