import os
import sys
import hashlib
import time
import json
import re
import traceback
from typing import Dict, Any, Optional
from app.settings import config
from app.llm_client import llm_client
from app.logger import get_logger

logger = get_logger("PageDiff")

# 导入自我纠错模块
try:
    from app.self_correction import self_correction_manager, ErrorSeverity, ErrorType
except ImportError:
    from self_correction import self_correction_manager, ErrorSeverity, ErrorType


class PageDiffManager:
    """页面变化检测管理器

    负责处理页面响应的快照存储、基线对比以及基于LLM的变化分析。
    支持任务隔离，每个任务ID拥有独立的缓存目录。
    """

    def __init__(self, task_id: str = "default"):
        """
        初始化页面差异管理器

        Args:
            task_id: 任务ID，用于隔离不同任务的缓存
        """
        self.task_id = task_id
        self.cache_dir = os.path.join(config.CACHE_DIR, task_id)
        if not os.path.exists(self.cache_dir):
            try:
                os.makedirs(self.cache_dir)
            except Exception as e:
                logger.warning(f"⚠️ 创建缓存目录失败: {e}")
                self_correction_manager.record_error(
                    node="PageDiffManager.__init__",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"创建缓存目录失败: {str(e)}",
                    severity=ErrorSeverity.MEDIUM
                )
            
    def _is_static_resource(self, url: str) -> bool:
        """判断是否为静态资源（无需对比）"""
        static_exts = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf', '.ico')
        path = url.split('?')[0].lower()
        return path.endswith(static_exts)

    def _get_file_path(self, url: str, content: bytes) -> str:
        """生成缓存文件路径
        格式: {url_hash}_{timestamp}_{内容md5}.html
        """
        url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
        timestamp = int(time.time())
        content_md5 = hashlib.md5(content).hexdigest()
        filename = f"{url_hash}_{timestamp}_{content_md5}.html"
        return os.path.join(self.cache_dir, filename)

    def cleanup_cache(self, max_age_seconds: int = 86400):
        """清理旧缓存文件 (默认24小时)"""
        now = time.time()
        count = 0
        if not os.path.exists(self.cache_dir):
            return
        
        logger.info("🧹 开始清理过期缓存...")
        for filename in os.listdir(self.cache_dir):
            file_path = os.path.join(self.cache_dir, filename)
            try:
                if os.path.isfile(file_path):
                    if now - os.path.getmtime(file_path) > max_age_seconds:
                        os.remove(file_path)
                        count += 1
            except Exception as e:
                logger.warning(f"⚠️ 删除失败 {filename}: {e}")
        
        if count > 0:
            logger.info(f"🧹 已清理 {count} 个旧缓存文件")

    def save_page(self, url: str, content: bytes, page_history: Dict[str, Any]) -> Dict[str, Any]:
        """保存页面响应并更新历史记录
        
        Args:
            url: 请求的URL
            content: 响应内容（bytes）
            page_history: 全局页面历史字典
            
        Returns:
            Dict: 本次保存的文件信息
        """
        if self._is_static_resource(url):
            return {}

        file_path = self._get_file_path(url, content)
        md5 = hashlib.md5(content).hexdigest()
        
        # 写入文件到缓存目录
        try:
            with open(file_path, 'wb') as f:
                f.write(content)
        except Exception as e:
            fail_icon = "❌" if (hasattr(sys.stdout, 'encoding') and sys.stdout.encoding and sys.stdout.encoding.lower() in ('utf-8', 'utf8')) else "[FAIL]"
            logger.warning(f"{fail_icon} 保存文件失败: {e}")
            return {}

        # 更新该URL的历史记录
        history = page_history.get(url, {
            "last_file": file_path,
            "last_md5": md5,
            "change_count": 0,
            "first_seen": time.time()
        })
        
        # 总是更新为最新的成功响应作为基线
        # 这意味着每次成功的请求都会成为下一次请求的基线
        history["last_file"] = file_path
        history["last_md5"] = md5
             
        page_history[url] = history
        
        return {
            "file_path": file_path,
            "md5": md5,
            "size": len(content),
            "timestamp": time.time()
        }

    def compare_and_analyze(self, url: str, current_content: bytes, page_history: Dict[str, Any]) -> Dict[str, Any]:
        """对比本次响应与基线，并分析差异

        Returns:
            Dict: 包含变化分析结果
        """
        if self._is_static_resource(url):
             return {"changed": False, "reason": "静态资源忽略"}

        current_md5 = hashlib.md5(current_content).hexdigest()
        current_str = current_content.decode('utf-8', errors='ignore')

        # 首次访问
        if url not in page_history:
            saved_info = self.save_page(url, current_content, page_history)
            return {
                "changed": True,
                "is_exploit": False,
                "confidence": 0.8,
                "reason": "首次发现新页面/路径",
                "score_adjustment": 0.0,
                "md5": current_md5,
                "file_path": saved_info.get("file_path")
            }

        history = page_history.get(url)
        last_md5 = history.get("last_md5")
        last_file = history.get("last_file")

        # MD5相同，无变化
        if current_md5 == last_md5:
            return {
                "changed": False,
                "reason": "MD5一致",
                "md5": current_md5,
                "score_adjustment": config.SCORE_NO_CHANGE,
                "file_path": last_file
            }

        # MD5不同，发生变化
        history["change_count"] = history.get("change_count", 0) + 1

        # 读取基线内容
        last_content = b""
        if last_file and os.path.exists(last_file):
            try:
                with open(last_file, 'rb') as f:
                    last_content = f.read()
            except Exception:
                pass

        # 保存新文件
        saved_info = self.save_page(url, current_content, page_history)
        current_file_path = saved_info.get("file_path")

        # 正则扫Flag (最优先)
        flag_pattern = r"(flag\{[a-zA-Z0-9_-]+\}|ctf\{[a-zA-Z0-9_-]+\}|NSSCTF\{[a-zA-Z0-9_-]+\})"
        flag_match = re.search(flag_pattern, current_str, re.IGNORECASE)
        if flag_match:
            extracted_flag = flag_match.group(0)
            logger.info(f"🎯 捕获到Flag: {extracted_flag}")
            return {
                "changed": True,
                "is_exploit": True,
                "confidence": 1.0,
                "reason": "发现Flag格式字符串",
                "score_adjustment": config.SCORE_CHANGE_EXPLOIT,
                "file_path": current_file_path,
                "extracted_flag": extracted_flag
            }

        # 让LLM判断变化是否有价值
        last_str = last_content.decode('utf-8', errors='ignore') if last_content else ""
        size_diff = abs(len(current_content) - len(last_content))

        analysis = self._analyze_change_with_llm(current_str, last_str, url, size_diff)

        score_adj = config.SCORE_CHANGE_EXPLOIT if analysis.get("is_exploit") else config.SCORE_CHANGE_NOT_EXPLOIT

        return {
            "changed": True,
            "is_exploit": analysis.get("is_exploit", False),
            "confidence": analysis.get("confidence", 0.0),
            "reason": analysis.get("reason", "模型分析结果"),
            "score_adjustment": score_adj,
            "file_path": current_file_path
        }

    def _analyze_change_with_llm(self, current_content: str, last_content: str, url: str, size_diff: int = 0) -> Dict[str, Any]:
        """使用LLM分析差异的具体含义

        Args:
            current_content: 当前响应内容
            last_content: 上次响应内容（基线）
            url: 请求的URL
            size_diff: 内容大小差异

        Returns:
            Dict: 包含 is_exploit, confidence, reason 的分析结果
        """
        max_retries = 3
        base_delay = 1.0

        for attempt in range(max_retries + 1):
            try:
                def truncate(content):
                    if len(content) > 4000:
                        return content[:2000] + "\n...[中间内容已省略]...\n" + content[-2000:]
                    return content

                snippet_curr = truncate(current_content)
                snippet_last = truncate(last_content) if last_content else "(首次访问，无基线)"

                prompt = f"""分析响应内容，判断是否为漏洞利用成功。

URL: {url}
变化大小: {size_diff} 字节

【当前响应】:
```
{snippet_curr}
```

【基线响应】:
```
{snippet_last}
```

判断是否为**成功**（is_exploit: true）：
- 文件上传成功：code=0, success=true, status=ok 等表示成功的JSON
- 命令执行回显：文件名、路径、用户名、系统信息
- 数据泄露：数据库报错、表名、字段名、数据内容
- FLAG出现：flag{{...}}, ctf{{...}} 等
- 新路径/文件：扫描发现的新资源

判断是否为**失败**（is_exploit: false）：
- 上传失败：code!=0, success=false, error message
- 无变化/无效响应：空白、无内容、动态时间戳

返回JSON：
{{
    "is_exploit": boolean,
    "confidence": float,
    "reason": "简短理由"
}}"""

                response = llm_client.call_chat_completion(
                    model=config.CHANGE_DETECTION_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    json_mode=True
                )

                if "```json" in response:
                    response = response.split("```json")[1].split("```")[0]
                elif "```" in response:
                    response = response.split("```")[1].split("```")[0]
                return json.loads(response)

            except json.JSONDecodeError as e:
                if attempt < max_retries:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                # 记录错误
                self_correction_manager.record_error(
                    node="PageDiffManager._analyze_change_with_llm",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"LLM响应JSON解析失败: {str(e)}",
                    severity=ErrorSeverity.LOW
                )
                return {"is_exploit": False, "confidence": 0.0, "reason": "模型解析失败"}

            except Exception as e:
                if attempt < max_retries:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                # 记录错误
                self_correction_manager.record_error(
                    node="PageDiffManager._analyze_change_with_llm",
                    error_type=ErrorType.LLM_TIMEOUT if "timeout" in str(e).lower() else ErrorType.EXECUTION_ERROR,
                    error_message=f"LLM调用失败: {str(e)}",
                    severity=ErrorSeverity.MEDIUM
                )
                return {"is_exploit": False, "confidence": 0.0, "reason": f"模型调用失败: {str(e)}"}

        return {"is_exploit": False, "confidence": 0.0, "reason": "重试次数耗尽"}

# 默认全局实例（用于无任务ID的场景）
page_diff_manager = PageDiffManager()

# 任务实例缓存字典
_task_managers: Dict[str, PageDiffManager] = {}


def get_page_diff_manager(task_id: str = "default") -> PageDiffManager:
    """
    获取指定任务的页面差异管理器

    Args:
        task_id: 任务ID，用于隔离缓存

    Returns:
        PageDiffManager: 该任务的页面差异管理器实例
    """
    if task_id not in _task_managers:
        _task_managers[task_id] = PageDiffManager(task_id)
    return _task_managers[task_id]


def clear_task_manager(task_id: str) -> bool:
    """
    清理指定任务的页面差异管理器

    Args:
        task_id: 任务ID

    Returns:
        bool: 是否成功清理
    """
    if task_id in _task_managers:
        manager = _task_managers[task_id]
        try:
            # 清理该任务的缓存目录
            if os.path.exists(manager.cache_dir):
                import shutil
                shutil.rmtree(manager.cache_dir)
        except Exception as e:
            self_correction_manager.record_error(
                node="page_diff.clear_task_manager",
                error_type=ErrorType.EXECUTION_ERROR,
                error_message=f"清理任务缓存失败: {str(e)}",
                severity=ErrorSeverity.LOW
            )
        del _task_managers[task_id]
        return True
    return False