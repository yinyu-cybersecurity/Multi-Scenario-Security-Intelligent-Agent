# tool_framework.py
import os
import uuid
import time
import json
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Optional

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
    """
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

# ==========================================
# 2. 命令行工具中间层
# ==========================================
class CommandLineTool(CTFTool):
    """所有需要通过本地命令行运行的工具的中间层基类"""
    def __init__(self, cmd_path: str):
        self.cmd_path = cmd_path
        self.timeout = 300  # 默认 5 分钟超时，适配大型扫描工具

    def _run_command(self, cmd: List[str], timeout: Optional[int] = None) -> Dict:
        """统一执行系统命令并捕获输出"""
        run_timeout = timeout or self.timeout
        process = None
        try:
            # 使用 Popen 以便在超时时能够杀死进程
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace"
            )

            try:
                stdout, stderr = process.communicate(timeout=run_timeout)
                return {
                    "success": process.returncode == 0,
                    "stdout": stdout,
                    "stderr": stderr,
                    "command": ' '.join(cmd)
                }
            except subprocess.TimeoutExpired:
                # [核心修复] 超时后强制杀死进程及其子进程
                process.kill()
                process.wait()  # 确保进程完全终止

                # [安全修复] 尝试获取已产生的部分输出，添加异常处理
                try:
                    stdout = process.stdout.read() if process.stdout else ""
                except (ValueError, OSError):
                    stdout = ""
                try:
                    stderr = process.stderr.read() if process.stderr else ""
                except (ValueError, OSError):
                    stderr = ""

                return {
                    "error": f"执行超时 ({run_timeout}秒)，进程已终止",
                    "command": ' '.join(cmd),
                    "stdout": stdout,
                    "stderr": stderr,
                    "timeout": True
                }
        except Exception as e:
            # 确保进程被清理
            if process and process.poll() is None:
                process.kill()
                process.wait()
            return {"error": str(e), "command": ' '.join(cmd)}

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
            print(f"[ToolRegistry] Registered: {tool.name()} (supports: {', '.join(tool.supported_vulns())})")

    @classmethod
    def get_tools(cls, vuln_type: str) -> List['CTFTool']:
        """供攻击兵查询使用：获取支持某类漏洞的所有工具"""
        return cls._tools.get(vuln_type, [])

    @classmethod
    def get_all_tools_info(cls) -> str:
        """
        获取所有注册工具的详细信息，用于构建 LLM Prompt。
        使用 set 确保每个工具只输出一次，防止 Weapon Manual 重复。

        requests 工具不在注册体系中，在此直接内嵌其规范。
        """
        info_lines = []
        seen_tools = set()

        # [核心修复] requests 不走注册流程，在此直接注入其参数规范
        requests_spec = {
            "method": {
                "type": "string",
                "description": "HTTP 方法，可选 GET/POST/PUT/DELETE，不填默认为 GET",
                "required": False,
                "default": "GET"
            },
            "url": {
                "type": "string",
                "description": "目标 URL，例如 http://example.com/vuln.php?id=1",
                "required": True
            },
            "params": {
                "type": "dict",
                "description": "URL 查询参数（?key=value），GET 请求或 POST 的 ? 部分",
                "required": False,
                "default": None
            },
            "data": {
                "type": "dict",
                "description": "POST 请求体（application/x-www-form-urlencoded）。Payload 可直接写入这里",
                "required": False,
                "default": None
            },
            "headers": {
                "type": "dict",
                "description": "自定义 HTTP 头。常用：Cookie、Content-Type、X-Forwarded-For、Referer、User-Agent",
                "required": False,
                "default": None
            },
            "files": {
                "type": "dict",
                "description": "文件上传（multipart/form-data）。三种方式："
                               "1. 直接内容: {\"upload\": (\"shell.php\", \"<?php system($_GET['c']);?>\", \"image/png\")}。"
                               "2. 使用已生成文件路径: {\"upload\": \"data/tool_outputs/shell.phar\"} (先用 file-creator 或 phar-gen 生成文件)。"
                               "3. 读取本地文件: {\"upload\": \"/path/to/file\"}。",
                "required": False,
                "default": None
            }
        }
        info_lines.append("### Tool: requests")
        info_lines.append("- Description: 发送 HTTP 请求，可完全控制 method/URL/headers/data/files，是手工 Payload 攻击的核心工具。")
        info_lines.append("- Supported Vulns: SQL Injection, Command Injection, XSS, SSRF, SSTI, File Upload, LFI, XXE, Authentication Bypass, Information Disclosure")
        info_lines.append(f"- Expected Params: {json.dumps(requests_spec, ensure_ascii=False)}")
        info_lines.append("")
        seen_tools.add("requests")

        for tools in cls._tools.values():
            for tool in tools:
                if tool.name() in seen_tools:
                    continue
                seen_tools.add(tool.name())

                info_lines.append(f"### Tool: {tool.name()}")
                info_lines.append(f"- Description: {tool.description()}")
                info_lines.append(f"- Supported Vulns: {', '.join(tool.supported_vulns())}")
                info_lines.append(f"- Expected Params: {json.dumps(tool.expected_params(), ensure_ascii=False)}")
                info_lines.append("")

        return "\n".join(info_lines)

    @classmethod
    def execute_cached(cls, tool_name: str, target: str, params: Dict) -> Dict:
        """供主图编排调用：执行工具并管理缓存，防止重复发包"""
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
            return {"error": f"Tool '{tool_name}' not registered!"}
        if not target_tool.check_available():
            return {"error": f"Tool '{tool_name}' not available! Check installation."}

        # 3. 跑工具
        print(f"[ToolRegistry] Executing: {tool_name} -> {target}")
        start_time = time.time()
        try:
            result = target_tool.execute(target, params)

            # 1. 提取并隔离原始输出用于物理日志存档
            # 注意：此时 result 应该是工具类 execute() 返回的结构化字典
            raw_content = ""
            if "stdout" in result: raw_content += str(result["stdout"])
            if "stderr" in result: raw_content += str(result["stderr"])
            if "raw_output" in result: raw_content += str(result["raw_output"])

            full_log_path = cls._save_to_file(tool_name, raw_content)
            result["full_log_path"] = full_log_path

            # 2. 内存精简：删除原始大型字段，仅保留结构化结论
            for field in ["stdout", "stderr", "raw_output"]:
                if field in result: del result[field]

            result["is_cleaned"] = True

        except Exception as e:
            result = {"error": f"Execution exception: {str(e)}"}
        duration = time.time() - start_time

        # 4. 写缓存
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