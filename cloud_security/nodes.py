# cloud_security/nodes.py
"""
云安全攻击节点

设计原则:
- 规则快速识别云服务商
- AI决策关键攻击策略
- 复用现有cloud_scanner工具
- 集成错误处理机制
"""

import os
import sys

# 确保项目根目录和app目录在 sys.path 中
_current_dir = os.path.dirname(__file__)
_project_root = os.path.dirname(_current_dir)
_app_dir = os.path.join(_project_root, 'app')
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

import json
import traceback
from typing import Dict, List
import requests

from app.llm_client import llm_client
from app.config import config
from app.logger import get_logger

logger = get_logger("CloudSecurity")

# 可选模块导入
try:
    from app.self_correction import self_correction_manager, ErrorSeverity, ErrorType
    SELF_CORRECTION_AVAILABLE = True
except ImportError:
    SELF_CORRECTION_AVAILABLE = False
    logger.debug("self_correction module not available")

# 可选工具导入
try:
    from tools.cloud_scanner import CloudScanner
    CLOUD_SCANNER_AVAILABLE = True
except ImportError:
    CLOUD_SCANNER_AVAILABLE = False
    logger.warning("cloud_scanner tool not available")


def _record_error(node: str, error_type: str, error_msg: str, severity: str = "MEDIUM"):
    """统一错误记录"""
    logger.error(f"[{node}] {error_type}: {error_msg}")
    if SELF_CORRECTION_AVAILABLE:
        sev = getattr(ErrorSeverity, severity, ErrorSeverity.MEDIUM)
        self_correction_manager.record_error(node, error_type, error_msg, sev)


def cloud_recon_node(state: Dict) -> Dict:
    """[云侦察] 识别云服务商和探测元数据"""
    target = state.get("current_url") or state.get("target", "")
    logger.info(f"[CloudRecon] 目标: {target}")

    updates = {
        "execution_steps": state.get("execution_steps", 0) + 1
    }

    # 复用现有工具检测
    if CLOUD_SCANNER_AVAILABLE:
        try:
            scanner = CloudScanner()
            result = scanner.execute(target, {"action": "enumerate"})

            providers = result.get("cloud_providers", [])
            provider = providers[0] if providers else ""

            if not provider:
                # 降级: 规则检测
                provider = _detect_provider(target)

            if not provider:
                updates.update({
                    "cloud_phase": "complete",
                    "cloud_provider": "",
                    "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
                })
                return updates

            # 探测元数据
            metadata_result = scanner.execute(target, {"action": "metadata"})
            metadata = metadata_result.get("metadata", {})

            updates.update({
                "cloud_provider": provider,
                "metadata_leaked": metadata,
                "detected_services": result.get("resources", []),
                "cloud_phase": "enum" if metadata or result.get("resources") else "complete"
            })
            return updates

        except Exception as e:
            _record_error("cloud_recon", ErrorType.TOOL_FAILURE if SELF_CORRECTION_AVAILABLE else "TOOL_FAILURE", str(e))
            # 降级: 规则检测

    # 降级路径
    provider = _detect_provider(target)
    metadata = _probe_metadata(provider) if provider else {}

    updates.update({
        "cloud_provider": provider,
        "metadata_leaked": metadata,
        "cloud_phase": "enum" if provider else "complete",
        "failure_weighted_score": state.get("failure_weighted_score", 0) + (0 if provider else 0.5)
    })
    return updates


def cloud_enum_node(state: Dict) -> Dict:
    """[云枚举] 枚举云资源"""
    provider = state.get("cloud_provider", "")
    target = state.get("current_url") or state.get("target", "")

    updates = {
        "execution_steps": state.get("execution_steps", 0) + 1
    }

    if not provider:
        updates["cloud_phase"] = "complete"
        return updates

    logger.info(f"[CloudEnum] 枚举 {provider}")

    # AI决策枚举策略
    enum_strategy = _ai_decide_enum_strategy(provider, state)

    # 执行枚举
    if CLOUD_SCANNER_AVAILABLE:
        try:
            scanner = CloudScanner()

            action_map = {"aws": "s3", "azure": "azure", "gcp": "gcp"}
            result = scanner.execute(target, {
                "action": action_map.get(provider, "enumerate"),
                "provider": provider,
                "keyword": enum_strategy.get("keyword", "")
            })

            buckets = result.get("buckets", [])
            resources = result.get("resources", [])

            updates.update({
                "buckets_found": [b.get("name", b) if isinstance(b, dict) else b for b in buckets],
                "iam_roles": [r.get("resource_id", "") for r in resources if "iam" in r.get("resource_type", "").lower()],
                "cloud_phase": "exploit" if buckets or resources else "complete"
            })
            return updates

        except Exception as e:
            _record_error("cloud_enum", ErrorType.EXECUTION_ERROR if SELF_CORRECTION_AVAILABLE else "EXECUTION_ERROR", str(e))

    updates.update({
        "cloud_phase": "complete",
        "failure_weighted_score": state.get("failure_weighted_score", 0) + 0.5
    })
    return updates


def cloud_exploit_node(state: Dict) -> Dict:
    """[云攻击] 攻击云资源"""
    buckets = state.get("buckets_found", [])
    credentials = state.get("temp_credentials", [])

    updates = {
        "execution_steps": state.get("execution_steps", 0) + 1
    }

    if not buckets and not credentials:
        updates["cloud_phase"] = "complete"
        return updates

    logger.info(f"[CloudExploit] 执行攻击")

    results = []
    secrets = {}

    # AI分析最有价值的攻击目标
    attack_priority = _ai_prioritize_targets(buckets, credentials, state)

    if CLOUD_SCANNER_AVAILABLE:
        for target_info in attack_priority[:3]:
            try:
                scanner = CloudScanner()
                result = scanner._check_s3_bucket(target_info.get("name", ""))
                if result:
                    results.append({
                        "target": target_info.get("name", ""),
                        "success": result.get("public", False),
                        "details": result
                    })
                    if result.get("sensitive_data"):
                        secrets[target_info.get("name", "")] = result.get("sensitive_data")
            except Exception as e:
                logger.debug(f"攻击失败: {e}")

    updates.update({
        "cloud_attack_results": results,
        "extracted_secrets": secrets,
        "cloud_phase": "escalate" if results else "complete",
        "failure_weighted_score": state.get("failure_weighted_score", 0) + (0 if results else 0.5)
    })
    return updates


def cloud_escalate_node(state: Dict) -> Dict:
    """[云提权] 权限提升分析"""
    credentials = state.get("temp_credentials", [])
    roles = state.get("iam_roles", [])

    updates = {
        "execution_steps": state.get("execution_steps", 0) + 1
    }

    if not credentials and not roles:
        updates["cloud_phase"] = "complete"
        return updates

    logger.info(f"[CloudEscalate] 分析提权路径")

    # AI分析提权可能
    paths = _ai_analyze_escalation(credentials, roles, state)

    updates.update({
        "escalation_paths": paths,
        "cloud_phase": "complete"
    })
    return updates


# =============================================================================
# AI决策函数 - 只在关键决策点使用AI
# =============================================================================

def _detect_provider(target: str) -> str:
    """规则快速检测云服务商"""
    patterns = {
        "aws": [".amazonaws.com", ".s3.amazonaws", ".cloudfront.net"],
        "azure": [".azurewebsites.net", ".blob.core.windows.net", ".vault.azure.net"],
        "gcp": [".appspot.com", ".storage.googleapis.com", ".run.app"],
        "alibaba": [".aliyuncs.com", ".oss-cn-"],
        "tencent": [".myqcloud.com", ".cos."]
    }
    target_lower = target.lower()
    for provider, pats in patterns.items():
        if any(p in target_lower for p in pats):
            return provider
    return ""


def _probe_metadata(provider: str) -> Dict:
    """探测云元数据服务"""
    metadata = {}
    if provider == "aws":
        endpoints = ["/latest/meta-data/iam/security-credentials/", "/latest/user-data"]
        for ep in endpoints:
            try:
                resp = requests.get(f"http://169.254.169.254{ep}", timeout=5)
                if resp.status_code == 200:
                    metadata[ep] = resp.text[:500]
            except:
                pass
    return metadata


def _ai_decide_enum_strategy(provider: str, state: Dict) -> Dict:
    """AI决策枚举策略 - 根据上下文智能选择"""
    prompt = f"""
分析云资源枚举策略。

云服务商: {provider}
已知信息: {list(state.get("metadata_leaked", {}).keys())}

返回JSON: {{"keyword": "枚举关键词", "targets": ["s3", "iam"]}}
"""
    try:
        resp = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, json_mode=True
        )
        if "```json" in resp:
            resp = resp.split("```json")[1].split("```")[0]
        return json.loads(resp.strip())
    except:
        return {"keyword": "", "targets": ["s3"]}


def _ai_prioritize_targets(buckets: List, credentials: List, state: Dict) -> List[Dict]:
    """AI优先级排序攻击目标"""
    if not buckets and not credentials:
        return []

    # 简单优先级: 有凭据的优先
    targets = []
    for b in buckets[:5]:
        targets.append({"name": b, "type": "bucket", "has_cred": bool(credentials)})
    return targets


def _ai_analyze_escalation(credentials: List, roles: List, state: Dict) -> List[str]:
    """AI分析提权路径"""
    if not credentials and not roles:
        return []

    prompt = f"""
分析云权限提升路径。

凭据数: {len(credentials)}
角色数: {len(roles)}

常见提权路径:
- iam:PutRolePolicy
- lambda:CreateFunction
- sts:AssumeRole

返回JSON: {{"paths": ["推荐的提权路径"]}}
"""
    try:
        resp = llm_client.call_chat_completion(
            model=config.ANALYST_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1, json_mode=True
        )
        if "```json" in resp:
            resp = resp.split("```json")[1].split("```")[0]
        return json.loads(resp.strip()).get("paths", [])
    except:
        return []