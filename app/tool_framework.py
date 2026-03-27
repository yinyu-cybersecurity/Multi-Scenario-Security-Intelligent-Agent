# tool_framework.py
"""
工具框架核心模块

提供:
- CTFTool: 工具抽象基类
- CommandLineTool: 命令行工具基类
- DockerTool: Docker容器工具基类
- ToolRegistry: 工具注册中心
- ToolResult: 统一的结果类型 (新增)
"""
import os
import uuid
import time
import json
import signal
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any, Generic, TypeVar
from dataclasses import dataclass, field

# ==========================================
# 0. 统一结果类型 (新增 - 任务1.1)
# ==========================================
T = TypeVar('T')

@dataclass
class ToolResult(Generic[T]):
    """
    统一的工具执行结果类型

    所有工具的 execute() 方法应返回符合此结构的 Dict
    确保 error 字段存在且格式一致
    """
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = {"success": self.success}
        if self.data is not None:
            result["data"] = self.data
        if self.error:
            result["error"] = self.error
        if self.raw_output:
            result["raw_output"] = self.raw_output
        return result

    @classmethod
    def ok(cls, data: Any = None, raw_output: str = "") -> 'ToolResult':
        """创建成功结果"""
        return cls(success=True, data=data, raw_output=raw_output)

    @classmethod
    def fail(cls, error: str, raw_output: str = "") -> 'ToolResult':
        """创建失败结果"""
        return cls(success=False, error=error, raw_output=raw_output)


def ensure_result_format(result: Dict) -> Dict:
    """
    确保结果字典包含必要字段

    统一处理不同格式的返回值，确保:
    - success 字段存在
    - error 字段存在（失败时）
    """
    if "success" not in result:
        # 推断 success
        result["success"] = "error" not in result and result.get("returncode", 0) == 0

    if not result.get("success") and "error" not in result:
        # 失败但无 error 字段，添加默认错误信息
        result["error"] = result.get("stderr", "Unknown error")

    return result

# 尝试导入 docker，如果环境没装不会阻断非 Docker 工具的运行
try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

# ==========================================
# 1. 最顶层抽象基类 (接口约束)
# ==========================================
class CTFTool(ABC):
    """
    所有安全工具的抽象基类。
    任何要接入系统的工具，都必须继承这个类（或其子类）并实现以下所有方法。

    前置条件属性（子类可覆盖）:
    - REQUIRES_CREDENTIALS: 是否需要凭据（默认False）
    - REQUIRES_SHELL_SESSION: 是否需要shell会话（默认False）
    - TOOL_CATEGORY: 工具类别 recon/attacker/internal（默认attacker）
    """

    # 默认前置条件（子类可覆盖）
    REQUIRES_CREDENTIALS: bool = False
    REQUIRES_SHELL_SESSION: bool = False
    TOOL_CATEGORY: str = "attacker"  # recon, attacker, internal

    @abstractmethod
    def name(self) -> str:
        """工具名称，如 'sqlmap', 'fenjing'"""
        pass

    @abstractmethod
    def description(self) -> str:
        """工具描述，用于告诉 LLM 这个工具的用途"""
        pass

    @abstractmethod
    def supported_vulns(self) -> List[str]:
        """支持的漏洞类型列表，如 ['sqli', 'time_sqli']"""
        pass

    def capability_statement(self) -> str:
        """
        工具能力声明 - 描述工具的适用场景和使用时机
        供LLM决策时参考，不硬编码具体漏洞

        示例: "漏洞扫描器。输入URL，自动扫描已知CVE漏洞。适合已识别框架、疑似CVE目标。"

        子类可覆盖此方法提供更详细的声明
        """
        return f"{self.description()} 支持漏洞类型: {', '.join(self.supported_vulns())}"

    @abstractmethod
    def execute(self, target: str, params: Dict) -> Dict:
        """执行工具的核心逻辑"""
        pass

    @abstractmethod
    def check_available(self) -> bool:
        """环境健康检查，返回 True 表示可用"""
        pass

    @abstractmethod
    def expected_params(self) -> Dict:
        """
        返回工具期望接收的参数规范（建议类似 JSON Schema 格式）。
        示例:
        {
            "command": {"type": "string", "description": "要执行的系统命令", "required": True},
            "level": {"type": "int", "description": "测试深度(1-5)", "default": 1, "required": False}
        }
        """
        pass

    def get_prerequisites(self) -> Dict[str, Any]:
        """
        获取工具的前置条件

        Returns:
            {
                "requires_credentials": bool,
                "requires_session": bool,
                "tool_category": str,
                "description": str  # 前置条件描述
            }
        """
        desc_parts = []
        if self.REQUIRES_CREDENTIALS:
            desc_parts.append("需要凭据")
        if self.REQUIRES_SHELL_SESSION:
            desc_parts.append("需要shell会话")

        return {
            "requires_credentials": self.REQUIRES_CREDENTIALS,
            "requires_session": self.REQUIRES_SHELL_SESSION,
            "tool_category": self.TOOL_CATEGORY,
            "description": "、".join(desc_parts) if desc_parts else "无特殊前置条件"
        }

    def check_prerequisites_met(self, state: Dict) -> Dict:
        """
        检查当前状态是否满足工具的前置条件

        Args:
            state: 当前状态，包含:
                - credentials: 凭据列表
                - shell_sessions: shell会话字典

        Returns:
            {
                "met": bool,  # 前置条件是否满足
                "missing": List[str],  # 缺失的条件
                "hint": str  # 提示信息
            }
        """
        missing = []

        # 检查凭据
        if self.REQUIRES_CREDENTIALS:
            credentials = state.get("credentials", [])
            if not credentials:
                missing.append("credentials")

        # 检查shell会话
        if self.REQUIRES_SHELL_SESSION:
            shell_sessions = state.get("shell_sessions", {})
            if not shell_sessions:
                missing.append("shell_session")

        met = len(missing) == 0
        hint = ""
        if not met:
            hint = f"工具 {self.name()} 需要: {', '.join(missing)}"

        return {
            "met": met,
            "missing": missing,
            "hint": hint
        }

# ==========================================
# 2. 命令行工具中间层
# ==========================================
class CommandLineTool(CTFTool):
    """所有需要通过本地命令行运行的工具的中间层基类"""
    def __init__(self, cmd_path: str):
        self.cmd_path = cmd_path
        self.timeout = 300  # 默认 5 分钟超时，适配大型扫描工具

    def _run_command(self, cmd: List[str], timeout: Optional[int] = None, stream_output: bool = True) -> Dict:
        """
        统一执行系统命令并捕获输出

        增强功能:
        - 使用进程组，确保超时时杀死所有子进程
        - 统一返回格式，包含 success 和 error 字段
        - 支持实时流输出到控制台
        """
        run_timeout = timeout or self.timeout
        process = None

        try:
            # 使用 start_new_session 创建新进程组，便于清理
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True  # 创建新进程组
            )

            # 实时流输出模式
            if stream_output:
                import threading
                import queue

                output_queue = queue.Queue()
                stdout_lines = []
                stderr_lines = []
                timed_out = False

                def read_stream(stream, stream_type):
                    """读取流并放入队列"""
                    try:
                        for line in iter(stream.readline, ''):
                            if line:
                                output_queue.put((stream_type, line.rstrip('\n')))
                                if stream_type == 'stdout':
                                    stdout_lines.append(line)
                                else:
                                    stderr_lines.append(line)
                    except Exception:
                        pass
                    finally:
                        stream.close()

                # 启动线程读取stdout和stderr
                stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, 'stdout'))
                stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, 'stderr'))
                stdout_thread.daemon = True
                stderr_thread.daemon = True
                stdout_thread.start()
                stderr_thread.start()

                # 实时打印输出
                start_time = time.time()
                while True:
                    # 检查超时（优先检查）
                    if time.time() - start_time > run_timeout:
                        timed_out = True
                        break

                    try:
                        stream_type, line = output_queue.get(timeout=0.1)
                        # 打印到控制台，带工具名前缀
                        if stream_type == 'stdout':
                            print(f"[{self.name()}] {line}")
                        else:
                            print(f"[{self.name()}][ERR] {line}")
                    except queue.Empty:
                        # 进程结束后，继续读取队列直到为空
                        if process.poll() is not None:
                            # 进程已结束，排空队列中剩余数据
                            while True:
                                try:
                                    stream_type, line = output_queue.get(timeout=0.05)
                                    if stream_type == 'stdout':
                                        print(f"[{self.name()}] {line}")
                                    else:
                                        print(f"[{self.name()}][ERR] {line}")
                                except queue.Empty:
                                    break
                            # 队列排空后退出
                            break

                # 超时处理
                if timed_out:
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        process.wait(timeout=2)
                    except:
                        try:
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                        except:
                            pass
                        process.wait()
                    print(f"[{self.name()}] 执行超时 ({run_timeout}秒)，已终止")

                # 等待线程结束
                stdout_thread.join(timeout=1)
                stderr_thread.join(timeout=1)

                stdout = ''.join(stdout_lines)
                stderr = ''.join(stderr_lines)

                if timed_out:
                    return ensure_result_format({
                        "success": False,
                        "error": f"执行超时 ({run_timeout}秒)，进程组已终止",
                        "command": ' '.join(cmd),
                        "stdout": stdout,
                        "stderr": stderr,
                        "timeout": True
                    })

                return ensure_result_format({
                    "success": process.returncode == 0,
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": process.returncode,
                    "command": ' '.join(cmd)
                })

            # 原有的阻塞模式
            try:
                stdout, stderr = process.communicate(timeout=run_timeout)
                return ensure_result_format({
                    "success": process.returncode == 0,
                    "stdout": stdout,
                    "stderr": stderr,
                    "returncode": process.returncode,
                    "command": ' '.join(cmd)
                })
            except subprocess.TimeoutExpired:
                # 超时后杀死整个进程组（包括子进程）
                try:
                    # 先尝试优雅终止
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    # 等待短暂时间
                    process.wait(timeout=2)
                except (subprocess.TimeoutExpired, ProcessLookupError, PermissionError):
                    # 如果还没死，强制杀死
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    process.wait()

                # [安全修复] 尝试获取已产生的部分输出
                stdout = ""
                stderr = ""
                try:
                    if process.stdout:
                        stdout = process.stdout.read()
                except (ValueError, OSError):
                    pass
                try:
                    if process.stderr:
                        stderr = process.stderr.read()
                except (ValueError, OSError):
                    pass

                return ensure_result_format({
                    "success": False,
                    "error": f"执行超时 ({run_timeout}秒)，进程组已终止",
                    "command": ' '.join(cmd),
                    "stdout": stdout,
                    "stderr": stderr,
                    "timeout": True
                })
        except FileNotFoundError as e:
            return ensure_result_format({
                "success": False,
                "error": f"命令未找到: {cmd[0] if cmd else 'unknown'}",
                "command": ' '.join(cmd)
            })
        except Exception as e:
            # 确保进程被清理
            if process and process.poll() is None:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    process.kill()
                process.wait()
            return ensure_result_format({
                "success": False,
                "error": str(e),
                "command": ' '.join(cmd)
            })

# ==========================================
# 网络扫描工具基类
# ==========================================
import re
from typing import Tuple

class NetworkScanTool(CommandLineTool):
    """
    网络扫描工具基类

    提供网络扫描工具的通用方法：
    - 目标验证（防止命令注入）
    - 端口验证
    - AI 结果分析框架

    子类只需实现具体的扫描逻辑和输出解析
    """

    # IP/域名/CIDR 验证正则
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    CIDR_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        r'/(?:[0-9]|[12][0-9]|3[0-2])$'
    )
    HOSTNAME_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    IPV6_PATTERN = re.compile(
        r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|'
        r'^::([0-9a-fA-F]{0,4}:){0,5}[0-9a-fA-F]{0,4}$|'
        r'^[0-9a-fA-F]{0,4}::([0-9a-fA-F]{0,4}:){0,5}[0-9a-fA-F]{0,4}$'
    )

    def __init__(self, cmd_path: str):
        super().__init__(cmd_path)
        # 网络扫描通常需要更长的超时
        self.timeout = 600  # 10分钟

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """
        验证目标参数，防止命令注入

        Args:
            target: 用户输入的目标地址（IP/域名/CIDR）

        Returns:
            (is_valid, error_message): 验证结果和错误信息

        Example:
            >>> tool.validate_target("192.168.1.1")
            (True, "")
            >>> tool.validate_target("192.168.1.1; rm -rf /")
            (False, "目标包含非法字符: ;")
        """
        if not target or not isinstance(target, str):
            return False, "目标不能为空"

        target = target.strip()

        # 长度限制
        if len(target) > 256:
            return False, "目标长度超过限制"

        # 检查危险字符（命令注入防护）
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in target:
                return False, f"目标包含非法字符: {char}"

        # 验证格式
        is_valid = (
            self.IPV4_PATTERN.match(target) or
            self.IPV6_PATTERN.match(target) or
            self.CIDR_PATTERN.match(target) or
            self.HOSTNAME_PATTERN.match(target)
        )

        if not is_valid:
            return False, f"无效的目标格式: {target}"

        return True, ""

    def validate_ports(self, ports: str) -> Tuple[bool, str]:
        """
        验证端口参数格式，防止命令注入

        Args:
            ports: 端口字符串，如 "80,443,8080-8090" 或 "1-65535"

        Returns:
            (is_valid, error_message): 验证结果和错误信息

        Example:
            >>> tool.validate_ports("80,443,8080-8090")
            (True, "")
            >>> tool.validate_ports("80; rm -rf /")
            (False, "端口格式非法，只允许数字、逗号和连字符")
        """
        if not ports:
            return True, ""

        ports = str(ports).strip()

        # 长度限制
        if len(ports) > 500:
            return False, "端口参数过长"

        # 特殊值：全端口扫描
        if ports == "-":
            return True, ""

        # 只允许数字、逗号、连字符
        if not re.match(r'^[\d,\-]+$', ports):
            return False, f"端口格式非法，只允许数字、逗号和连字符: {ports}"

        # 验证每个端口/范围
        for part in ports.split(','):
            part = part.strip()
            if not part:
                continue

            if '-' in part:
                # 端口范围
                parts = part.split('-')
                if len(parts) != 2:
                    return False, f"端口范围格式错误: {part}"

                try:
                    start, end = int(parts[0]), int(parts[1])
                    if not (1 <= start <= 65535 and 1 <= end <= 65535):
                        return False, f"端口超出有效范围 (1-65535): {part}"
                    if start > end:
                        return False, f"端口范围起始大于结束: {part}"
                except ValueError:
                    return False, f"端口范围格式错误: {part}"
            else:
                # 单个端口
                try:
                    port = int(part)
                    if not (1 <= port <= 65535):
                        return False, f"端口超出有效范围 (1-65535): {part}"
                except ValueError:
                    return False, f"端口格式错误: {part}"

        return True, ""

    def ai_analyze_results(
        self,
        target: str,
        hosts: List[Dict],
        vulns: List[Dict],
        scan_type: str = "network"
    ) -> Dict:
        """
        AI 分析扫描结果

        Args:
            target: 扫描目标
            hosts: 发现的主机列表
            vulns: 发现的漏洞列表
            scan_type: 扫描类型 (network/web)

        Returns:
            分析结果，包含 summary 和 recommendations
        """
        if not hosts and not vulns:
            return {
                "summary": "未发现存活主机或漏洞",
                "recommendations": []
            }

        # 构建摘要
        summary_parts = []
        if hosts:
            summary_parts.append(f"发现 {len(hosts)} 台主机")
        if vulns:
            summary_parts.append(f"{len(vulns)} 个漏洞")

        summary = "，".join(summary_parts) if summary_parts else "扫描完成"

        return {
            "summary": summary,
            "recommendations": []  # 子类可覆盖此方法提供更详细的分析
        }

# ==========================================
# 3. Docker 容器工具中间层
# ==========================================
class DockerTool(CTFTool):
    """所有需要隔离在 Docker 容器中运行的工具的中间层基类"""
    def __init__(self, image_name: str):
        if not HAS_DOCKER:
            raise ImportError("缺少 docker 库，请运行 `pip install docker`")
        
        self.client = docker.from_env()
        self.image = image_name
        self.timeout = 60  # 容器默认 60 秒超时

    def _run_container(self, command: str) -> Dict:
        """动态拉起容器运行命令，运行完毕自动销毁"""
        try:
            # 检查并拉取镜像
            try:
                self.client.images.get(self.image)
            except docker.errors.ImageNotFound:
                print(f"🐳 正在拉取镜像 {self.image}，请稍候...")
                self.client.images.pull(self.image)

            # 运行容器 (使用 host 网络以便访问本地靶机)
            container = self.client.containers.run(
                self.image,
                command,
                detach=True,
                remove=True,
                network_mode="host" 
            )
            
            # 等待执行完毕并获取日志
            result = container.wait(timeout=self.timeout)
            logs = container.logs().decode('utf-8', errors='replace')
            
            return {
                "success": result['StatusCode'] == 0,
                "output": logs
            }
        except Exception as e:
            return {"error": str(e), "success": False}

# ==========================================
# 4. 工具注册中心 (大管家)
# ==========================================
class ToolRegistry:
    """工具注册中心 - 单例模式，管理所有接入的武器"""
    _instance = None
    _tools: Dict[str, List['CTFTool']] = {}
    _cache: Dict[str, Dict] = {}

    # 缓存配置
    CACHE_MAX_SIZE = 1000  # 最大缓存条目数
    CACHE_MAX_AGE = 3600   # 缓存过期时间（秒）

    # 使用相对路径，这样 Windows 本地和 Docker 都能正常工作
    # 在 Docker 中，WORKDIR 是 /app，所以 data 依然在 /app/data
    OUTPUT_DIR = os.path.join("data", "tool_outputs")

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Ensure output directory exists
            os.makedirs(cls.OUTPUT_DIR, exist_ok=True)
        return cls._instance


    @classmethod
    def _save_to_file(cls, tool_name: str, content: str) -> str:
        """原始日志强制保存到本地文档，绝不进入上下文"""
        # 使用相对路径适配所有环境
        output_dir = os.path.join("data", "tool_raw_logs")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        filename = f"{tool_name}_{int(time.time())}_{uuid.uuid4().hex[:6]}.log"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    @classmethod
    def register(cls, tool: 'CTFTool'):
        """自动注册工具并按支持的漏洞类型建立索引"""
        # 检查工具是否已经注册过（通过名称判断）
        already_registered = False

        # 检查工具是否可用
        available = tool.check_available()

        for vuln_type in tool.supported_vulns():
            if vuln_type not in cls._tools:
                cls._tools[vuln_type] = []

            existing_tool_names = [t.name() for t in cls._tools[vuln_type]]
            if tool.name() in existing_tool_names:
                already_registered = True
            else:
                cls._tools[vuln_type].append(tool)

        # 只在第一次注册时打印
        if not already_registered:
            status = "✅" if available else "❌"
            print(f"[ToolRegistry] {status} {tool.name()} (supports: {', '.join(tool.supported_vulns())}) - {'available' if available else 'unavailable'}")

    @classmethod
    def get_tools(cls, vuln_type: str) -> List['CTFTool']:
        """供攻击兵查询使用：获取支持某类漏洞的所有工具"""
        return cls._tools.get(vuln_type, [])

    @classmethod
    def get_all_tools(cls) -> List['CTFTool']:
        """获取所有已注册的唯一工具列表"""
        seen_names = set()
        unique_tools = []
        for tools in cls._tools.values():
            for tool in tools:
                if tool.name() not in seen_names:
                    seen_names.add(tool.name())
                    unique_tools.append(tool)
        return unique_tools

    @classmethod
    def get_tool_names(cls) -> List[str]:
        """获取所有已注册工具的名称列表"""
        return [tool.name() for tool in cls.get_all_tools()]

    @classmethod
    def get_tool_by_name(cls, name: str) -> Optional['CTFTool']:
        """根据名称获取工具实例"""
        for tool in cls.get_all_tools():
            if tool.name() == name:
                return tool
        return None

    @classmethod
    def tool_exists(cls, name: str) -> bool:
        """检查工具是否已注册"""
        return cls.get_tool_by_name(name) is not None

    @classmethod
    def get_statistics(cls) -> Dict[str, Any]:
        """获取工具注册统计信息"""
        unique_tools = cls.get_all_tools()
        return {
            "total_tools": len(unique_tools),
            "vuln_types": len(cls._tools),
            "tool_names": [t.name() for t in unique_tools],
            "vuln_type_names": list(cls._tools.keys())
        }

    @classmethod
    def get_all_tools_info(cls, scenes: Dict = None) -> str:
        """
        获取所有注册工具的能力声明，用于构建 LLM Prompt。

        Args:
            scenes: 可选的场景信息，用于在输出中标记相关工具
        """
        info_lines = []
        seen_tools = set()

        # requests 工具的能力声明
        info_lines.append("## Tool: requests")
        info_lines.append("手工HTTP请求工具。可控制method/URL/headers/data/files。适合：手工Payload构造、绕过检测、文件上传攻击、验证新路径。")
        info_lines.append("")
        seen_tools.add("requests")

        for tools in cls._tools.values():
            for tool in tools:
                if tool.name() in seen_tools:
                    continue
                seen_tools.add(tool.name())

                info_lines.append(f"## Tool: {tool.name()}")
                info_lines.append(tool.capability_statement())
                info_lines.append("")

        return "\n".join(info_lines)

    @classmethod
    def check_tool_prerequisites(cls, tool_name: str, state: Dict) -> Dict:
        """
        检查工具的前置条件是否满足

        Args:
            tool_name: 工具名称
            state: 当前状态，包含:
                - credentials: 凭据列表
                - shell_sessions: shell会话字典

        Returns:
            {
                "can_execute": bool,
                "missing": List[str],
                "hint": str,
                "prerequisites": Dict  # 工具的前置条件信息
            }
        """
        tool = cls.get_tool_by_name(tool_name)
        if not tool:
            return {
                "can_execute": False,
                "missing": ["tool_not_registered"],
                "hint": f"工具 '{tool_name}' 未注册",
                "prerequisites": {}
            }

        check_result = tool.check_prerequisites_met(state)
        return {
            "can_execute": check_result["met"],
            "missing": check_result["missing"],
            "hint": check_result["hint"],
            "prerequisites": tool.get_prerequisites()
        }

    @classmethod
    def get_tools_by_category(cls, category: str) -> List['CTFTool']:
        """
        按类别获取工具列表

        Args:
            category: "recon", "attacker", "internal"

        Returns:
            该类别的工具列表
        """
        return [t for t in cls.get_all_tools() if t.TOOL_CATEGORY == category]

    @classmethod
    def get_tools_requiring_credentials(cls) -> List[str]:
        """获取需要凭据的工具名称列表"""
        return [t.name() for t in cls.get_all_tools() if t.REQUIRES_CREDENTIALS]

    @classmethod
    def get_tools_requiring_session(cls) -> List[str]:
        """获取需要shell会话的工具名称列表"""
        return [t.name() for t in cls.get_all_tools() if t.REQUIRES_SHELL_SESSION]

    @classmethod
    def execute_cached(cls, tool_name: str, target: str, params: Dict) -> Dict:
        """
        供主图编排调用：执行工具并管理缓存，防止重复发包

        增强功能:
        - 统一结果格式
        - 错误恢复机制入口
        """
        cache_key = f"{tool_name}:{target}:{json.dumps(params, sort_keys=True)}"

        # 0. 清理过期缓存（每次调用时检查）
        cls._cleanup_cache()

        # 1. 查缓存
        if cache_key in cls._cache:
            cached_entry = cls._cache[cache_key]
            # 检查缓存是否过期
            if time.time() - cached_entry.get("timestamp", 0) < cls.CACHE_MAX_AGE:
                print(f"[ToolCache] Hit: {tool_name} -> {target}")
                return {"cached": True, "result": cached_entry["result"], "duration": 0.0}
            else:
                # 缓存过期，删除
                del cls._cache[cache_key]

        # 2. 找工具
        target_tool: Optional['CTFTool'] = None
        for tlist in cls._tools.values():
            for t in tlist:
                if t.name() == tool_name:
                    target_tool = t
                    break
            if target_tool: break

        if not target_tool:
            return ensure_result_format({
                "success": False,
                "error": f"Tool '{tool_name}' not registered!",
                "cached": False
            })
        if not target_tool.check_available():
            return ensure_result_format({
                "success": False,
                "error": f"Tool '{tool_name}' not available! Check installation.",
                "cached": False
            })

        # 3. 跑工具
        print(f"[ToolRegistry] Executing: {tool_name} -> {target}")
        start_time = time.time()
        try:
            result = target_tool.execute(target, params)

            # 确保结果格式统一
            result = ensure_result_format(result)

            # 1. 提取原始输出用于日志和AI解析
            raw_content = ""
            if "stdout" in result: raw_content += str(result["stdout"])
            if "stderr" in result: raw_content += str(result["stderr"])
            if "raw_output" in result: raw_content += str(result["raw_output"])

            # 保存完整日志
            if raw_content:
                full_log_path = cls._save_to_file(tool_name, raw_content)
                result["full_log_path"] = full_log_path

            # 2. AI解析输出（如果结果没有结构化数据且执行成功）
            if result.get("success") and not result.get("vulnerabilities") and not result.get("hosts") and raw_content:
                try:
                    from tool_output_parser import parse_output
                    parsed = parse_output(tool_name, raw_content, target)
                    # 合并解析结果
                    if parsed.get("success"):
                        result["vulnerabilities"] = parsed.get("vulnerabilities", [])
                        result["hosts"] = parsed.get("hosts", [])
                        result["credentials"] = parsed.get("credentials", [])
                        result["attack_paths"] = parsed.get("attack_paths", [])
                        result["summary"] = parsed.get("summary", "")
                        result["domain_info"] = parsed.get("domain_info", {})
                except Exception as e:
                    print(f"[ToolRegistry] AI parse failed: {e}")

            # 3. 内存精简：删除原始大型字段
            for field_name in ["stdout", "stderr", "raw_output"]:
                if field_name in result:
                    del result[field_name]

            result["is_cleaned"] = True

        except Exception as e:
            result = ensure_result_format({
                "success": False,
                "error": f"Execution exception: {str(e)}"
            })

        duration = time.time() - start_time
        result["duration"] = duration

        # 4. 写缓存（只缓存成功的结果）
        if result.get("success"):
            cls._cache[cache_key] = {"result": result, "timestamp": time.time()}

        return {"cached": False, "result": result, "duration": duration}

    @classmethod
    def _cleanup_cache(cls):
        """清理过期和超量缓存"""
        current_time = time.time()

        # 清理过期缓存
        expired_keys = [
            k for k, v in cls._cache.items()
            if current_time - v.get("timestamp", 0) > cls.CACHE_MAX_AGE
        ]
        for k in expired_keys:
            del cls._cache[k]

        # 如果缓存超量，删除最旧的条目
        if len(cls._cache) > cls.CACHE_MAX_SIZE:
            # 按时间戳排序，删除最旧的
            sorted_keys = sorted(
                cls._cache.keys(),
                key=lambda k: cls._cache[k].get("timestamp", 0)
            )
            keys_to_remove = sorted_keys[:len(cls._cache) - cls.CACHE_MAX_SIZE]
            for k in keys_to_remove:
                del cls._cache[k]

    @classmethod
    def clear_cache(cls):
        """清空所有缓存"""
        cls._cache.clear()
        print("[ToolRegistry] Cache cleared")