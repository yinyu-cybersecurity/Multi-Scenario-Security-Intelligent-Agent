# app/scene_detector.py
"""
场景检测器 - 从页面特征中提取场景信息
不做判断，只提取特征，决策交给LLM
"""

import re
import json
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs


class SceneDetector:
    """
    场景检测器

    职责：从侦察结果中提取结构化的场景信息
    不做：漏洞判断、工具推荐（交给LLM）
    """

    def detect(self, page_features: dict, baseline: dict, raw_html: str = "") -> Dict[str, Any]:
        """
        检测场景信息

        Args:
            page_features: 页面特征（tech_stack, input_vectors等）
            baseline: 基线响应（server, headers, detected_frameworks等）
            raw_html: 原始HTML

        Returns:
            结构化的场景信息
        """
        scenes = {
            "framework": [],      # 检测到的框架/中间件
            "input_vectors": [],  # 输入点
            "sensitive_paths": [],# 敏感路径
            "data_patterns": [],  # 数据特征
            "service_info": {},   # 服务信息
            "hints": []           # 其他线索
        }

        # 1. 框架检测
        scenes["framework"] = self._detect_frameworks(baseline, raw_html)

        # 2. 输入向量检测
        scenes["input_vectors"] = self._detect_input_vectors(page_features, baseline, raw_html)

        # 3. 敏感路径检测
        scenes["sensitive_paths"] = self._detect_sensitive_paths(page_features, raw_html)

        # 4. 数据模式检测
        scenes["data_patterns"] = self._detect_data_patterns(baseline, raw_html)

        # 5. 服务信息
        scenes["service_info"] = self._detect_service_info(baseline)

        # 6. 其他线索
        scenes["hints"] = self._detect_hints(page_features, baseline, raw_html)

        return scenes

    def _detect_frameworks(self, baseline: dict, raw_html: str) -> List[Dict]:
        """检测框架/中间件"""
        frameworks = []

        # 从baseline获取已检测的框架
        for fw in baseline.get("detected_frameworks", []):
            frameworks.append({
                "name": fw.get("name", ""),
                "version": fw.get("version", ""),
                "source": "header"
            })

        # 从Server头检测
        server = baseline.get("server", "").lower()
        if server:
            # 提取版本信息
            version_match = re.search(r'[/\s](\d+\.\d+(?:\.\d+)?)', server)
            version = version_match.group(1) if version_match else ""
            name = server.split("/")[0].strip()

            # 避免重复
            if not any(f["name"].lower() == name for f in frameworks):
                frameworks.append({
                    "name": name,
                    "version": version,
                    "source": "Server header"
                })

        # 从HTML检测
        html_lower = raw_html.lower()

        # 常见框架指纹
        framework_patterns = {
            "ThinkPHP": [r"thinkphp", r"think_template"],
            "Laravel": [r"laravel", r"laravel_session"],
            "Spring": [r"whitelabel error page", r"springframework"],
            "Django": [r"csrfmiddlewaretoken", r"django"],
            "Flask": [r"flask", r"werkzeug"],
            "Express": [r"express", r"x-powered-by.*express"],
            "Struts": [r"struts", r".action"],
        }

        for fw_name, patterns in framework_patterns.items():
            if any(re.search(p, html_lower) for p in patterns):
                if not any(f["name"].lower() == fw_name.lower() for f in frameworks):
                    frameworks.append({
                        "name": fw_name,
                        "version": "",
                        "source": "html content"
                    })

        return frameworks

    def _detect_input_vectors(self, page_features: dict, baseline: dict, raw_html: str) -> List[Dict]:
        """检测输入向量"""
        vectors = []

        # 从page_features获取
        for vec in page_features.get("input_vectors", []):
            # 解析格式 "GET:id" 或 "POST:username"
            if ":" in vec:
                method, param = vec.split(":", 1)
                vectors.append({
                    "type": "parameter",
                    "method": method.upper(),
                    "name": param,
                    "location": "URL" if method.upper() == "GET" else "body"
                })

        # 从URL参数检测
        final_url = baseline.get("final_url", "")
        if "?" in final_url:
            try:
                parsed = urlparse(final_url)
                params = parse_qs(parsed.query)
                for param_name in params:
                    if not any(v["name"] == param_name and v["type"] == "parameter" for v in vectors):
                        vectors.append({
                            "type": "parameter",
                            "method": "GET",
                            "name": param_name,
                            "location": "URL"
                        })
            except Exception:
                pass

        # 从表单检测
        html_lower = raw_html.lower()

        # 登录表单
        if "<form" in html_lower and ("password" in html_lower or "pass" in html_lower or "login" in html_lower):
            vectors.append({
                "type": "form",
                "name": "login",
                "hint": "登录表单，可能存在弱口令或SQL注入"
            })

        # 文件上传
        if 'type="file"' in html_lower or "multipart/form-data" in html_lower:
            vectors.append({
                "type": "form",
                "name": "file_upload",
                "hint": "文件上传点"
            })

        # 搜索框
        if 'type="search"' in html_lower or ("search" in html_lower and "<input" in html_lower):
            vectors.append({
                "type": "form",
                "name": "search",
                "hint": "搜索框，可能存在SQL注入或XSS"
            })

        return vectors

    def _detect_sensitive_paths(self, page_features: dict, raw_html: str) -> List[str]:
        """检测敏感路径"""
        paths = set()

        # 从page_features获取
        for path in page_features.get("sensitive_paths", []):
            paths.add(path)

        # 常见敏感路径模式
        sensitive_patterns = [
            r'href=["\']([^"\']*(?:admin|manager|config|backup|git|svn|env|flag)[^"\']*)["\']',
            r'src=["\']([^"\']*(?:api|test|debug)[^"\']*)["\']',
            r'action=["\']([^"\']+)["\']',
        ]

        for pattern in sensitive_patterns:
            matches = re.findall(pattern, raw_html, re.IGNORECASE)
            for match in matches:
                if match.startswith("/") or match.startswith("http"):
                    paths.add(match)

        return list(paths)[:20]  # 限制数量

    def _detect_data_patterns(self, baseline: dict, raw_html: str) -> List[Dict]:
        """检测数据模式"""
        patterns = []

        # JWT
        if re.search(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', raw_html):
            patterns.append({"type": "jwt", "hint": "发现JWT token"})

        # Base64
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', raw_html):
            patterns.append({"type": "base64", "hint": "可能存在Base64编码数据"})

        # 序列化数据
        if "O:" in raw_html or "a:" in raw_html:
            if re.search(r'O:\d+:', raw_html) or re.search(r'a:\d+:{', raw_html):
                patterns.append({"type": "php_serialized", "hint": "PHP序列化数据"})

        if "rO0AB" in raw_html or "aced0005" in raw_html.lower():
            patterns.append({"type": "java_serialized", "hint": "Java序列化数据"})

        # Shiro rememberMe
        cookies = str(baseline.get("cookies", {}))
        if "rememberme" in cookies.lower():
            patterns.append({"type": "shiro_cookie", "hint": "Shiro rememberMe cookie"})

        # 加密数据
        if re.search(r'[a-f0-9]{32,}', raw_html):
            patterns.append({"type": "hex_hash", "hint": "可能的哈希值"})

        return patterns

    def _detect_service_info(self, baseline: dict) -> Dict:
        """检测服务信息"""
        info = {}

        server = baseline.get("server", "")
        if server:
            info["server"] = server

        x_powered_by = baseline.get("x_powered_by", "")
        if x_powered_by:
            info["x_powered_by"] = x_powered_by

        # 端口信息
        final_url = baseline.get("final_url", "")
        if final_url:
            try:
                parsed = urlparse(final_url)
                port = parsed.port
                if port:
                    info["port"] = port
                elif parsed.scheme == "https":
                    info["port"] = 443
                else:
                    info["port"] = 80
            except Exception:
                pass

        return info

    def _detect_hints(self, page_features: dict, baseline: dict, raw_html: str) -> List[str]:
        """检测其他线索"""
        hints = []

        # 技术栈
        tech_stack = page_features.get("tech_stack", [])
        if tech_stack:
            hints.append(f"技术栈: {', '.join(tech_stack)}")

        # 状态码
        status = baseline.get("status_code", 0)
        if status == 403:
            hints.append("访问被拒绝(403)，可能需要认证或绕过")
        elif status == 401:
            hints.append("需要认证(401)")
        elif status == 500:
            hints.append("服务器错误(500)，可能存在漏洞")

        # 重定向
        redirect_chain = baseline.get("redirect_chain", [])
        if redirect_chain:
            hints.append(f"发生{len(redirect_chain)}次重定向")

        # SQL报错
        sql_errors = ["sql syntax", "mysql", "oracle", "postgresql", "sqlite"]
        html_lower = raw_html.lower()
        for err in sql_errors:
            if err in html_lower and "error" in html_lower:
                hints.append("发现SQL错误信息")
                break

        # 源码泄露线索
        if ".git" in raw_html or ".svn" in raw_html:
            hints.append("可能存在版本控制信息泄露")

        # 注释中的线索
        comments = re.findall(r'<!--(.*?)-->', raw_html, re.DOTALL)
        for comment in comments:
            if any(kw in comment.lower() for kw in ["todo", "fixme", "password", "secret", "key", "debug"]):
                hints.append(f"HTML注释发现线索: {comment.strip()[:50]}")
                break

        return hints

    def format_for_llm(self, scenes: Dict) -> str:
        """将场景信息格式化为LLM可读的文本"""
        lines = []

        if scenes.get("framework"):
            fw_str = ", ".join([
                f"{fw['name']}" + (f"/{fw['version']}" if fw.get('version') else "")
                for fw in scenes["framework"]
            ])
            lines.append(f"**已识别框架**: {fw_str}")

        if scenes.get("input_vectors"):
            vec_strs = []
            for vec in scenes["input_vectors"]:
                if vec["type"] == "parameter":
                    vec_strs.append(f"{vec['method']}参数: {vec['name']}")
                elif vec["type"] == "form":
                    vec_strs.append(f"表单: {vec['name']}" + (f" ({vec.get('hint', '')})" if vec.get('hint') else ""))
            if vec_strs:
                lines.append(f"**输入向量**: {'; '.join(vec_strs)}")

        if scenes.get("sensitive_paths"):
            lines.append(f"**敏感路径**: {', '.join(scenes['sensitive_paths'][:5])}")

        if scenes.get("data_patterns"):
            pattern_strs = [p.get("hint", p["type"]) for p in scenes["data_patterns"]]
            lines.append(f"**数据特征**: {', '.join(pattern_strs)}")

        if scenes.get("service_info"):
            info = scenes["service_info"]
            info_parts = []
            if info.get("server"):
                info_parts.append(f"Server: {info['server']}")
            if info.get("port"):
                info_parts.append(f"Port: {info['port']}")
            if info_parts:
                lines.append(f"**服务信息**: {', '.join(info_parts)}")

        if scenes.get("hints"):
            lines.append(f"**其他线索**: {'; '.join(scenes['hints'][:5])}")

        return "\n".join(lines) if lines else "无特殊场景信息"