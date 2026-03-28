# evolution.py - 进化闭环
# 作用：成功时触发，将经验沉淀为永久规则，实现"越用越强"
# 核心机制：LLM归纳 + 结构化去重 + 动态置信度 + 优胜劣汰 + 老化机制

import time
import re
import json
import os
import hashlib

from typing import Dict, List

from logger import get_logger

logger = get_logger("Evolution")


# 规则文件路径
RULES_FILE = "learned_rules.json"
BACKUP_DIR = "rules_backup"


class EvolutionManager:
    """进化管理器 - 负责规则的全生命周期管理"""

    def __init__(self, rules_file: str = RULES_FILE):
        self.rules_file = rules_file
        self.rules = self._load_rules()
        self._ensure_backup_dir()

    def _ensure_backup_dir(self):
        """确保备份目录存在"""
        os.makedirs(BACKUP_DIR, exist_ok=True)

    def _load_rules(self) -> List[Dict]:
        """加载现有规则"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"加载规则失败: {e}")
                return []
        return []

    def _save_rules(self):
        """持久化规则（带备份）"""
        try:
            # 保存主文件
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, indent=2, ensure_ascii=False)

            # 保存备份（每小时一次）
            backup_file = os.path.join(BACKUP_DIR, f"rules_{int(time.time())}.json")
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, indent=2, ensure_ascii=False)

            # 清理旧备份（保留最近10个）
            self._cleanup_backups()

        except Exception as e:
            logger.warning(f"保存规则失败: {e}")

    def _cleanup_backups(self, keep: int = 10):
        """清理旧备份"""
        backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith("rules_")])
        for old in backups[:-keep]:
            os.remove(os.path.join(BACKUP_DIR, old))

    def _age_rules(self):
        """规则老化 - 删除长期未使用的归档规则"""
        now = int(time.time())
        MAX_AGE = 30 * 24 * 3600  # 30天

        before = len(self.rules)
        self.rules = [r for r in self.rules if not (
                r.get("status") == "archived" and
                now - r.get("last_seen", now) > MAX_AGE
        )]
        after = len(self.rules)

        if before > after:
            logger.info(f"规则老化: 删除 {before - after} 条过期规则")

    def calculate_fingerprint(self, rule: Dict) -> str:
        """
        计算规则指纹 - 用于结构化去重
        指纹 = hash(漏洞类型 + 关键特征 + 适用技术栈)
        """
        pattern = rule.get("pattern", "")
        # 简化pattern，去除具体的数值和随机字符串，只保留结构
        simplified_pattern = re.sub(r'=\d+', '={VAL}', pattern)
        simplified_pattern = re.sub(r'[\'"][a-zA-Z0-9]{32}[\'"]', '"{HASH}"', simplified_pattern)
        simplified_pattern = re.sub(r'[a-f0-9]{40}', '{SHA1}', simplified_pattern, flags=re.I)

        # 组合指纹因子
        factors = [
            rule.get("type", "unknown"),
            simplified_pattern,
            rule.get("condition", {}).get("tech_stack", "any")
        ]

        fingerprint_str = "|".join(str(f) for f in factors)
        return hashlib.md5(fingerprint_str.encode()).hexdigest()

    def merge_rule(self, new_rule: Dict) -> bool:
        """
        合并新规则 - 实现去重和强化
        
        Returns:
            bool: True表示是全新规则，False表示是已有规则（进行了强化）
        """
        new_fp = self.calculate_fingerprint(new_rule)
        
        for rule in self.rules:
            # 1. 指纹匹配（强一致性）
            if self.calculate_fingerprint(rule) == new_fp:
                self._reinforce_rule(rule, new_rule)
                return False
            
            # 2. 语义相似度匹配（弱一致性，防止变种泛滥）
            if rule.get("type") == new_rule.get("type") and \
               (rule.get("pattern") in new_rule.get("pattern") or new_rule.get("pattern") in rule.get("pattern")):
                self._reinforce_rule(rule, new_rule)
                return False

        # 全新规则，加入库中
        new_rule["id"] = new_fp[:8]
        new_rule["created_at"] = int(time.time())
        new_rule["last_seen"] = int(time.time())
        new_rule["hit_count"] = 1
        new_rule["confidence"] = 0.6  # 新规则初始置信度
        new_rule["status"] = "incubating" # 孵化中
        
        self.rules.append(new_rule)
        # self._save_rules() # 移除单次保存，改为批量保存
        return True

    def _reinforce_rule(self, old_rule: Dict, new_rule: Dict):
        """强化已有规则 - 提升置信度"""
        logger.info(f"  🔄 规则强化: {old_rule.get('type')} (ID: {old_rule.get('id')})")
        
        # 提升置信度 (上限 0.95)
        old_rule["confidence"] = min(0.95, old_rule.get("confidence", 0.5) + 0.05)
        old_rule["hit_count"] = old_rule.get("hit_count", 0) + 1
        old_rule["last_seen"] = int(time.time())
        
        # 如果是归档/孵化状态且再次命中，复活/转正
        if old_rule.get("status") in ["incubating", "archived"]:
            old_rule["status"] = "active"
            logger.info(f"  🎉 规则激活: {old_rule.get('id')} 状态变更为 active")
            
        # 如果是归档规则复活，重置老化时间
        if old_rule.get("status") == "archived":
            old_rule["created_at"] = int(time.time()) 

        # self._save_rules() # 移除单次保存

    def evaluate_rule_effectiveness(self, rule_id: str, success: bool):
        """
        评估规则有效性 (供外部调用)

        Args:
            rule_id: 规则ID
            success: 本次尝试是否成功
        """
        for rule in self.rules:
            if rule.get("id") == rule_id:
                if success:
                    self._reinforce_rule(rule, {})
                else:
                    # 失败惩罚机制优化
                    rule["confidence"] = max(0.1, rule.get("confidence", 0.5) - 0.01)

                    # 优胜劣汰逻辑优化
                    if rule.get("confidence") < 0.2 and rule.get("hit_count") == 0:
                        rule["status"] = "archived"
                        logger.info(f"  🗑️ 规则归档: {rule_id} (低置信度且无成功记录)")

                self._save_rules()
                break

    def extract_rule_via_heuristics(self, action: Dict) -> Dict:
        """
        基于启发式的规则提取 (兜底方案)
        当LLM不可用或提取失败时使用
        """
        payload = action.get("payload", "")
        ctx = action.get("context", {})
        vuln_type = ctx.get("type", "unknown")
        location = action.get("location", "")

        rule = {
            "type": vuln_type,
            "pattern": payload[:200],  # 限制长度
            "location_type": "param" if "?" in location else "path",
            "condition": {
                "tech_stack": ctx.get("tech", "any")
            },
            "description": f"Auto-extracted {vuln_type} rule"
        }

        # 简单的泛化逻辑
        if vuln_type == "sqli":
            # 提取参数名
            param_match = re.search(r'[?&](\w+)=', payload)
            if param_match:
                rule["param"] = param_match.group(1)

            if "UNION SELECT" in payload.upper():
                rule["subtype"] = "union_based"
            elif "SLEEP" in payload.upper():
                rule["subtype"] = "time_based"
            elif "OR" in payload.upper() and "=" in payload:
                rule["subtype"] = "auth_bypass"

        elif vuln_type == "xss":
            if "<script>" in payload:
                rule["subtype"] = "reflected_xss"
            elif "onerror" in payload:
                rule["subtype"] = "event_xss"

        elif vuln_type == "lfi":
            if "etc/passwd" in payload:
                rule["subtype"] = "passwd_leak"
            elif "php://filter" in payload:
                rule["subtype"] = "php_filter"

        return rule

    def export_to_strategy_filter(self) -> Dict[str, List[str]]:
        """
        导出为策略过滤器可用的格式
        返回: { "tech_stack": ["vuln_type1", "vuln_type2"] }
        """
        result = {}

        for rule in self.rules:
            if rule.get("status") != "active":
                continue

            tech = rule.get("condition", {}).get("tech_stack", "any")
            vuln_type = rule.get("type")

            if tech not in result:
                result[tech] = []
            if vuln_type not in result[tech]:
                result[tech].append(vuln_type)

        return result


def evolution_node(state: CTFState) -> Dict:
    """
    进化闭环 - 深度优化版 (支持全链条学习)
    """
    logger.info("🧬 启动进化引擎...")

    # 1. 严格验证成功
    if not state.get("found_flag"):
        return {}

    trace = state.get("success_trace", [])
    if not trace:
        logger.warning("  ⚠️ 缺少成功回溯信息，无法进化")
        return {}

    manager = EvolutionManager()
    new_rules_count = 0
    reinforced_count = 0

    # 2. 分析整个攻击链条
    # [核心修复] 严格筛选：只有真正产生 Flag 的步骤才参与进化
    # 放宽条件：
    #   - diff_analysis.is_exploit == True（强烈信号：PageDiff 判定为利用成功）
    #   - extracted_flag 存在（直接捕获到 Flag 内容）
    #   - output 中包含 flag 关键字（中等信号，可能是报错泄露）
    # 不再依赖 status == 200，因为正常页面返回200但并非利用
    significant_steps = [step for step in trace if
                         step.get("is_exploit") is True or
                         step.get("extracted_flag") or
                         ("flag" in str(step.get("output", "")).lower() and
                          any(kw in str(step.get("output", "")).lower()
                              for kw in ["flag{", "ctf{", "nssctf{", "nssctf{"]))]

    if not significant_steps:
        # 兜底：确实没有任何显著步骤时，不进行任何学习，直接退出
        logger.warning("  ⚠️ 未发现有效攻击路径，跳过本次学习")
        return {}

    logger.info(f"  🔗 正在从 {len(significant_steps)} 个关键步骤中提取攻击链条...")

    for step in significant_steps:
        # 跳过信息不足的步骤
        if not step.get("payload") or step.get("payload") == "N/A":
            continue

        # [核心修复] 跳过没有实际攻击意义的结果
        # 排除：只有 "flag" 关键字但实际是错误提示的响应
        output_text = str(step.get("output", ""))
        if "flag" in output_text.lower() and not step.get("is_exploit") and not step.get("extracted_flag"):
            # 检查是否是错误页面或无意义回显（通过关键词判断）
            noise_keywords = ["not defined", "undefined", "error", "invalid", "forbidden", "denied"]
            if any(kw in output_text.lower() for kw in noise_keywords):
                logger.info(f"  ⏭️ 跳过噪声步骤: {step.get('tool')} (output含'flag'但为无意义噪声)")
                continue

        logger.info(f"  🧪 分析动作: {step.get('tool')} -> {step.get('target', 'unknown')}")

        # 3. 规则提取与合并
        rule_candidate = manager.extract_rule_via_heuristics(step)

        # [核心修复] 补充完整上下文信息
        if step.get("diff_analysis"):
            da = step["diff_analysis"]
            rule_candidate["description"] = f"Reason: {da.get('reason', 'N/A')}"

        # 如果该步骤直接捕获到了 Flag，标记为成功案例
        if step.get("extracted_flag"):
            rule_candidate["is_success_case"] = True
            rule_candidate["extracted_flag"] = step["extracted_flag"]
            logger.info(f"  🏆 成功案例: {step.get('tool')} -> Flag: {step['extracted_flag']}")

        is_new = manager.merge_rule(rule_candidate)
        
        if is_new:
            new_rules_count += 1
            logger.info(f"  ✨ 习得新技能: {rule_candidate.get('type')}")
        else:
            reinforced_count += 1

    # 4. 批量保存与老化处理
    manager._age_rules()
    manager._save_rules()

    logger.info(f"🧬 进化完成: 新增 {new_rules_count} 条规则, 强化 {reinforced_count} 条规则")
    logger.info(f"               规则库总规模: {len(manager.rules)} 条")

    return {"permanent_rules": manager.rules}
