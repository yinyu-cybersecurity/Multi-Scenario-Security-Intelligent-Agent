"""
CTF 指导 Agent (Advisor)

职责：
1. 监控主 Agent 思考质量，适时干预
2. 语义压缩上下文，消除失败记录淹没
3. 分析失败原因，注入上下文提示
4. 后台实时侦察：预测阶段 → 提前侦察 → 确认注入

设计原则：
- 容错优先：advisor 调用失败不影响主流程
- 轻量快速：评估上下文小，token 消耗低
- 建议式干预：不强制拒绝，只提醒和建议
- 预测驱动：提前侦察下一阶段资源，确认后立即注入
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from app.logger import get_logger

logger = get_logger("Advisor")


# ============================================================================
# 提示词模板
# ============================================================================

ADVISOR_SYSTEM_PROMPT = """## 身份

你是 CTF 渗透任务的**指导顾问**（Advisor）。你监控主渗透 Agent（Operator）的思考过程，在它偏离轨道时给予指引。

你有**前瞻性**能力：能根据当前攻击阶段预测 Operator 接下来应该做什么，在它偏离合理路径时**提前干预**。

你不执行任何工具调用，不直接攻击目标。你只做五件事：
1. **监控注意力** — Operator 的思考是否变得空洞、无目标、无计划？
2. **检查资源遗忘** — Operator 是否在盲目尝试，但忽略了已知可用的工具或信息？
3. **检查记忆遗漏** — Operator 是否获得了关键信息（凭据、端点、漏洞）但没有调用 remember 记录？
4. **纠正明显错误** — Operator 是否在做已知会失败的事情？
5. **前瞻性预测** — 基于当前阶段，预测 Operator 接下来应该做什么？它下一步是否在合理路径上？

## 工具侦察能力

当你准备给出干预建议时，你**不是盲目推荐工具名**，而是基于下方的"工具侦察报告"来给出**精准、可执行的推荐**：

### 推荐原则
- **单一方案工具**（如 frp 隧道）：只推荐一个最合适的方案，给出具体配置思路
- **模板类工具**（如 nuclei）：推荐 1-3 个具体模板名或模板路径模式
- **Skill 类知识**：推荐 1-2 个具体 Skill 文件名，说明为什么选它
- **避免泛泛而谈**：不说"用 nuclei 扫描"，而是说"用 nuclei -t http/cves/2023/CVE-2023-XXXX.yaml 扫描"

### 推荐格式（嵌入在 guidance 中）
```
[TOOL] 推荐工具：具体命令或配置
[TEMPLATE] 推荐模板：具体模板路径或搜索模式
[SKILL] 推荐技能：具体 skill 文件名 + 为什么
```

## 你的知识

### 可用工具
- Kali 工具集：fscan、nmap、nuclei、sqlmap、hydra、hashcat、msfconsole、ffuf、frp、mimikatz、bloodhound、impacket 等
- MCP 工具：bash（执行命令）、http（HTTP 请求）、read/write（文件操作）、remember/recall（记忆）、search_skills/read_skill（攻击知识库）
- 比赛工具：list_challenges、start_challenge、stop_challenge、submit_flag、view_hint

### 关键字典
- /usr/share/wordlists/rockyou.txt
- /usr/share/seclists/
- /usr/share/nuclei-templates/（12920 个 PoC 模板）

### 攻击知识库
124 个 SKILL.md 文件，覆盖：Web 漏洞、内网渗透、OA 系统、AD 域攻击、云安全、密码学

### 标准攻击节奏
- 信息收集 → 漏洞发现 → 漏洞利用 → 提权 → 横向移动 → 目标达成
- 每个阶段完成后，进入下一阶段，不要跳跃
- 同一方向 3 次失败后必须换方向

### 关键提醒
- 获取 shell 后标准动作：whoami → sudo -l → id → env → 信息收集
- 内网渗透标准动作：发现网段 → 建立隧道(frp/ssh/chisel) → 扫描 → 横向移动
- OOB 外带用内网 IP（bash: hostname -I），不要用 127.0.0.1
- 文件传输：Kali 启动 HTTP server → 目标 wget / write 工具 base64 编码
- Flag 格式：flag{...}，发现立即 submit_flag
- 相同输入 = 相同输出，不要重复已失败的尝试
- **关键信息必须 remember**：凭据、端点、漏洞点、sudo 权限、内网拓扑"""


# ============================================================================
# 评估 Prompt — 统一模板 + 分阶段标准
# ============================================================================

_EVALUATE_BASE_TEMPLATE = """## 任务

{stage_title}

{stage_intro}

### Operator 最近的思考

{thinking_history}

### Operator 最近的操作

{recent_actions}

### 最近工具结果（如果有）

{recent_results}

### 已知进度摘要

{progress_summary}

### 循环检测器状态

{loop_status}

### 历史建议（Advisor 之前给出但未被确认的建议）

{previous_guidance}

### 侦察缓存（当前各阶段可用资源）

{recon_context}

---

{criteria_text}

---

请输出你的判断。格式：

```json
{{
  "need_intervention": true/false,
  "suggest_challenge_switch": true/false,
  "reason": "为什么需要/不需要干预（50字以内）",
  "guidance": "如果需要干预，给出具体的指导消息。如果不需要，留空。",
  "predicted_next_steps": ["步骤1", "步骤2", "步骤3"],
  "unaddressed_guidance": ["仍未被采纳的历史建议（由你自行判断，不要包含已解决的）"]
}}
```

**suggest_challenge_switch 规则**：
- 当同一题目超过 20 分钟无明显进展时设为 true
- 当同一方法重复失败 5 次以上时设为 true
- 当存在更简单明显的其他题目时设为 true

指导消息的要求（必须遵守）：
1. **长度**：200-400 字，不要一句话敷衍
2. **格式**：必须按以下三段式结构输出：
   - **【已知事实】**：列出你从 Operator 最近的行动中观察到的具体事实（用了什么工具、得到了什么结果、忽略了什么信息）
   - **【问题分析】**：基于事实分析问题所在（方向错误？工具选择不当？遗漏关键信息？效率低下？）
   - **【具体行动指令】**：给出明确可执行的下一步操作，包括具体工具名、命令模式、skill 文件名、模板路径等
3. **必须要求 Operator 回应**：结尾使用问句，如"你是否看到了？打算怎么处理？"
4. 如果有循环检测器报告的信息，结合它给出更精准的判断
5. 如果工具结果显示了关键信息被 Operator 忽略，指出具体内容
6. `predicted_next_steps` 必须列出 1-3 个具体的下一步行动
7. `unaddressed_guidance` 列出仍然未被采纳的历史建议（如果有的话）

**好的指导消息示例**：
```
【已知事实】你在 SQL 注入上已经连续失败了 4 次：sqlmap 无结果、手动 payload 无报错、WAF 拦截了 3 次请求。你已知的线索是目标使用 ThinkPHP 5.0.23。
【问题分析】你在同一个方向（SQL 注入）反复尝试但方法单一，没有查找 ThinkPHP 5.0.23 的已知漏洞。这属于"用猜代替查"。
【具体行动指令】立即执行 searchsploit thinkphp 5.0.23 查找已知 EXP，然后用 nuclei -t http/cves/2023/ 扫描相关 CVE。如果需要技术细节，调用 search_skills('thinkphp rce')。
你是否看到了这个问题？打算立即执行哪个方案？
```"""

# 分阶段评估标准 — 每个阶段只关注 3 个核心维度
# 格式：(stage_title, stage_intro, criteria_text)
_STAGE_CRITERIA = {
    "recon": (
        "## 任务：侦察阶段评估",
        "Operator 处于**信息收集阶段**。关注以下 3 点：",
        """**1. 覆盖面检查**：
- 扫描范围够不够？是否只扫了部分端口/服务？
- 是否遗漏了关键信息（版本、技术栈、入口点）？
- 有没有跳过侦察直接尝试攻击？

**2. 效率评估**：
- 侦察速度合理吗？是否在一个目标上花费太久？
- 是否在重复扫描同一目标？

**3. 下一步规划**：
- 根据已发现的服务，预测接下来最可能的攻击面"""
    ),

    "vuln_discovery": (
        "## 任务：漏洞发现阶段评估",
        "Operator 正在**扫描和发现漏洞**。关注以下 3 点：",
        """**1. 扫描策略检查**：
- 是否在用 nuclei 等工具做针对性扫描？
- 是否忽略了已发现的漏洞线索（如错误信息、异常响应）？
- 是否在同一个漏洞上反复尝试不同工具？

**2. 效率评估**：
- 每个目标扫描时间是否合理？
- 是否有结果但 Operator 没有深入分析？
- 连续 3 次无发现后是否换了方向？

**3. 下一步规划**：
- 发现漏洞后，Operator 是否在做正确的利用准备？"""
    ),

    "vuln_exploit": (
        "## 任务：漏洞利用阶段评估",
        "Operator 正在**利用漏洞**。关注以下 3 点：",
        """**1. Payload 检查**：
- 找到漏洞后，Operator 是否在查找/构造正确的 payload？
- 是否在用 searchsploit / nuclei PoC / skill 知识？
- 同一个 payload 连续失败后是否换了方法？

**2. 攻击前思考**：
- Operator 是否在盲目发送 payload 而不分析漏洞原理？
- 是否确认了利用条件（版本匹配、WAF、权限）？

**3. 时间检查**：
- 如果超过20分钟未成功利用，建议换漏洞或换题"""
    ),

    "privesc": (
        "## 任务：提权阶段评估",
        "Operator 正在**尝试提权**。关注以下 3 点：",
        """**1. 权限检查**：
- 获取 shell 后是否执行了标准动作：whoami → sudo -l → id → env？
- 是否忽略了已发现的提权信息（sudo 权限、SUID 文件）？

**2. 提权路径**：
- 是否在尝试已知可用的提权方法？
- 连续失败后是否换了提权向量？

**3. 时间检查**：
- 超过15分钟未提权成功，检查是否遗漏了更简单的路径"""
    ),

    "lateral": (
        "## 任务：横向移动阶段评估",
        "Operator 正在**内网横向移动**。关注以下 3 点：",
        """**1. 网络拓扑**：
- 是否已识别内网结构和可用隧道？
- 是否建立了稳定的代理/隧道连接（frp/chisel/ssh）？

**2. 横向路径**：
- 是否在用正确的内网扫描方法？
- 是否发现了新的凭据但没有使用？

**3. 时间检查**：
- 横向移动通常较慢，但超过25分钟无进展需检查策略"""
    ),

    "objective": (
        "## 任务：目标达成阶段评估",
        "Operator 正在**尝试读取 flag / 完成目标**。关注以下 3 点：",
        """**1. Flag 检测**：
- 是否已经找到 flag 但没有提交？
- 是否在读取 flag 时遇到权限问题？

**2. 最后一步检查**：
- flag 格式是 flag{...}，是否识别到了但没注意到？

**3. 多 Flag 检查**：
- 题目是否有多个 flag？是否只找到了一个？"""
    ),
}

# 完整 8 维度评估标准 — 未知阶段时 fallback
_FULL_CRITERIA = """请评估：

**1. 注意力评估**：
- Operator 的思考是否有明确的目标和计划？
- 还是在机械地尝试不同工具但没有思考为什么？
- 思考质量相比之前是提升了还是下降了？

**2. 资源检查**：
- Operator 是否在忽略已知可用的工具？
- Operator 是否在忽略已获得的信息？
- Operator 是否知道查看 SKILL.md 获取攻击指引？

**3. 方向评估**：
- Operator 当前的方向合理吗？
- 是否有更直接的路径被忽略了？
- 是否存在"用不同工具做同一件事"的模式？

**4. 错误检测**：
- Operator 是否在重复已失败的操作？
- 是否有违反标准攻击节奏的行为？

**5. "3次失败换方向"原则检查**（关键）：
- Operator 是否在同一端点/方法上连续失败 3 次以上？
- 如果是，Operator 是否已经换了方向？
- 如果没有换方向，**必须立即干预**，强制要求换方向

**6. 循环确认**：
- 循环检测器是否报告了重复模式？
- 如果有，Operator 是否在调整策略？

**7. 前瞻性预测**（最重要的部分）：
- 基于当前攻击阶段，预测接下来 3 步应该做什么？
- Operator 的下一步行动是否在合理路径上？
- 如果 Operator 正在做偏离路径的事（如发现 RCE 后不去利用而去读通用技能），立即干预！
- **预测性干预的优先级高于事后评估**。如果 Operator 的下一步明显偏离了合理路径，`need_intervention` 必须为 true

**8. 进度与时间评估**（关键）：
   - 估算当前挑战已花费的时间（根据消息轮数、工具调用频率）
   - 如果超过20分钟（约150轮）无明显进展，明确建议换题
   - 判断当前是"已找到突破口可深入"还是"仍在盲目尝试"
   - 如果连续10轮以上没有实质性发现，发出强烈警告
   - 记录之前建议的时间节点，跟踪是否改善

**9. 历史建议跟踪**（由你自行判断）：
- 上方"历史建议"中列出了你之前给出的建议。**请根据最近的工具调用和操作，判断这些建议是否已被采纳。**
- 如果已采纳：从 `unaddressed_guidance` 中移除
- 如果未采纳：保留在 `unaddressed_guidance` 中，并在本次干预中升级语气
- 升级语气示例："我在第X轮建议你做Y，之后又提醒了一次，但你仍未执行。请解释原因或立即执行。"
- 如果历史建议已不适用（场景已变化），可以从 `unaddressed_guidance` 中移除"""


COMPRESS_PROMPT = """## 任务

你正在压缩 CTF 渗透任务的对话历史。请阅读以下完整对话记录，生成一份精简的进度摘要。

### 完整对话历史

{conversation_text}

---

请生成进度摘要（500 字以内），包含：

**1. 当前状态**（1 句话）— 当前在攻击哪个目标？处于什么阶段？
**2. 已获取的信息**（列举）— 开放端口、已知漏洞、已获取凭据、内网拓扑
**3. 已尝试的方法**（简要）— 哪些成功？哪些失败？失败原因？
**4. 当前障碍**（1-2 句话）— 现在卡在什么地方？
**5. 下一步建议**（1-2 句话）— 基于当前状态，最合理的下一步？
**6. 已完成题目**（比赛模式）— 已找到哪些 flag？

**重要**：如果对话中包含 Advisor 的指导消息（以 [GUIDANCE] 开头），必须提取其中的关键信息到摘要中。这些是之前发现的重要提醒。

---

输出格式：纯文本，简洁明了。只保留关键事实，不记录推理过程。

示例：
```
当前：已获取 webshell (www-data)，尝试读取 /root/flag/flag01.txt
已知：80/443/8080 开放，ThinkPHP 5.0.23 RCE，内网 172.22.1.0/24
凭据：root:mysql空密码，sudo -l 显示 (root) NOPASSWD: /usr/bin/mysql
已尝试：6 种方式读 flag 均失败（权限不足），未检查 sudo 权限
Advisor 提醒：忽略 sudo -l 检查，mysql 提权效率低
障碍：无法读取 root 目录下的 flag
建议：sudo mysql -uroot -proot 直接提权
```"""


ASSESSMENT_PROMPT = """## 任务

你是 CTF 渗透任务的 Advisor。请阅读主 Agent 最近的思考和操作，判断当前状态并预测下一步。

### 最近的思考（最近 10 条消息）

{recent_messages}

### 最近的工具调用（最近 5 次）

{recent_tools}

### 上次预测（如果有的话）

{last_prediction}

### 当前侦察缓存（如果有）

{recon_cache}

---

请判断：

1. **当前阶段**：主 Agent 正在做什么？从以下选择：
   - recon（信息收集：端口扫描、服务识别）
   - vuln_discovery（漏洞发现：nuclei 扫描、sqlmap、目录扫描）
   - vuln_exploit（漏洞利用：payload 投递、获取 shell）
   - privesc（提权：sudo 提权、SUID、内核漏洞）
   - lateral（横向移动：内网扫描、隧道、域渗透）
   - objective（目标达成：读取 flag、最终提权）

2. **预测下一步**：基于当前阶段和攻击节奏，预测主 Agent 接下来最可能做什么？
   - 标准节奏：recon → vuln_discovery → vuln_exploit → privesc → lateral → objective
   - 但要根据实际情况调整

3. **需要侦察吗**：如果预测的下一阶段和上次不同，需要侦察新资源

4. **预测确认吗**：如果上次预测和当前判断一致，说明预测正确

输出 JSON:
```json
{{
  "current_stage": "recon|vuln_discovery|vuln_exploit|privesc|lateral|objective",
  "predicted_next": "下一阶段名 或 null",
  "need_recon": true/false,
  "recon_query": "搜索关键词（如果需要侦察，如 'sqli bypass' 或 'lateral movement'）",
  "prediction_match": "correct|changed|confirmed"
}}
```

预测确认判断：
- "correct"：当前阶段和上次预测一致 → 可以注入侦察结果
- "changed"：当前阶段和上次预测不同 → 需要调整
- "confirmed"：主 Agent 已经开始做预测的事 → 立即注入"""


# ============================================================================
# 核心类
# ============================================================================

class CTFAdvisor:
    """CTF 指导 Agent — 监控、评估、语义压缩、后台侦察注入"""

    def __init__(self, model: str, llm_client):
        self._model = model
        self._client = llm_client
        self._last_summary = ""
        # 后台侦察循环状态
        self._recon_cache: Dict[str, Dict[str, Dict]] = {}  # {challenge_code: {stage: data}}
        self._challenge_progress_cache: Dict[str, str] = {}  # {challenge_code: summary} — 题目关闭时保存的进度摘要
        self._current_recon_challenge_code: Optional[str] = None  # 当前挑战的 recon 缓存 key
        self._predicted_stage: Optional[str] = None  # 上次预测的阶段
        self._current_stage: Optional[str] = None  # 当前评估的攻击阶段
        self._recon_task: Optional[asyncio.Task] = None  # 当前侦察任务
        self._last_messages_len: int = 0  # 上次处理的 messages 长度
        self._running: bool = False  # 后台循环运行标志
        self._processing: bool = False  # 防止并发处理
        self._background_task: Optional[asyncio.Task] = None  # 后台任务句柄
        # 按挑战隔离的思考 buffer
        self._thinking_buffers: Dict[str, str] = {}  # {challenge_code: thinking_text}
        self._current_thinking_challenge_code: Optional[str] = None
        # 挑战开始时间追踪（用于进度警告）
        self._challenge_start_time: Dict[str, float] = {}  # {challenge_code: timestamp}
        self._last_time_warning_turn: Dict[str, int] = {}  # {challenge_code: turn_number}

    def set_current_challenge(self, challenge_code: str):
        """设置当前挑战，隔离各挑战的 recon 缓存和 thinking buffer"""
        self._current_recon_challenge_code = challenge_code
        self._current_thinking_challenge_code = challenge_code
        # 记录开始时间
        self._challenge_start_time[challenge_code] = asyncio.get_event_loop().time()
        # 确保该挑战的缓存存在
        if challenge_code not in self._recon_cache:
            self._recon_cache[challenge_code] = {}
        # 强制清空该挑战的 thinking buffer（防止残留旧思考）
        self._thinking_buffers[challenge_code] = ""
        if challenge_code not in self._last_time_warning_turn:
            self._last_time_warning_turn[challenge_code] = 0
        logger.info(f"[Advisor] Set current challenge: {challenge_code} (isolated state)")

    def get_current_thinking(self) -> str:
        """获取当前挑战的思考 buffer"""
        if self._current_thinking_challenge_code:
            return self._thinking_buffers.get(self._current_thinking_challenge_code, "")
        return ""

    def append_to_thinking(self, text: str, max_chars: int = 8000):
        """向当前挑战的 thinking buffer 追加内容"""
        key = self._current_thinking_challenge_code or "_default_"
        if key not in self._thinking_buffers:
            self._thinking_buffers[key] = ""
        self._thinking_buffers[key] += text
        if len(self._thinking_buffers[key]) > max_chars:
            self._thinking_buffers[key] = self._thinking_buffers[key][-max_chars:]

    def reset_thinking_buffer(self):
        """仅重置 thinking buffer（上下文压缩时调用，不清空 recon 缓存）"""
        self._thinking_buffers.clear()
        self._current_thinking_challenge_code = None

    def reset_for_new_challenge(self):
        """完整重置所有挑战状态（切题时调用）"""
        self._recon_cache.clear()
        self._thinking_buffers.clear()
        self._challenge_start_time.clear()
        self._last_time_warning_turn.clear()
        self._current_recon_challenge_code = None
        self._current_thinking_challenge_code = None
        # 注意：不清空 _challenge_progress_cache，切题后仍保留

    def save_challenge_progress(self, code: str, summary: str):
        """保存某道题的进度摘要（题目关闭时调用）"""
        if code and summary:
            self._challenge_progress_cache[code] = summary[:2000]
            logger.info(f"[Advisor] Saved progress for challenge {code}")

    def get_challenge_progress(self, code: str) -> Optional[str]:
        """获取某道题的历史进度（重新开始时注入）"""
        return self._challenge_progress_cache.get(code)

    def _get_current_challenge_cache(self) -> Optional[Dict[str, Dict]]:
        """获取当前挑战的 recon 缓存（按 stage 隔离）"""
        if self._current_recon_challenge_code:
            return self._recon_cache.get(self._current_recon_challenge_code)
        return None

    async def evaluate(
        self,
        thinking_history: str,
        recent_actions: list,
        progress_summary: str = "",
        recent_results: str = "",
        loop_detected: Optional[Dict] = None,
        previous_guidance: Optional[List[str]] = None,
        turns_since_last_intervention: int = 0,
        recent_tools: Optional[List[str]] = None,
    ) -> Tuple[Optional[str], List[str]]:
        """
        评估主 Agent 的思考质量，返回干预消息（如果需要）。

        Args:
            thinking_history: 最近 N 轮 assistant message 的思考内容
            recent_actions: 最近 N 轮 tool_calls 摘要
            progress_summary: 上一次语义压缩的摘要（如果有）
            recent_results: 最近工具执行结果（成功/失败）
            loop_detected: Loop Detector 状态（如果有）
            previous_guidance: 之前未采纳的 Advisor 建议列表（由 Advisor 自行维护）
            turns_since_last_intervention: 上次干预到现在经过的轮数
            recent_tools: 最近执行的工具名称列表

        Returns:
            (干预消息字符串或None, 未采纳建议列表)
        """
        try:
            if previous_guidance is None:
                previous_guidance = []
            if recent_tools is None:
                recent_tools = []

            actions_text = ""
            for i, action in enumerate(recent_actions[:5], 1):
                func = action.get("function", {}) if isinstance(action, dict) else {}
                name = func.get("name", str(action))
                args = func.get("arguments", "{}")
                actions_text += f"{i}. {name}({args[:100]})\n"

            # 最近工具列表（供 Advisor 判断建议是否被采纳）
            tools_text = ", ".join(recent_tools[-5:]) if recent_tools else "无"

            # 循环检测器状态
            if loop_detected:
                loop_text = (
                    f"[循环检测器报告] 共检测到 {loop_detected.get('total_loops', 0)} 次循环\n"
                    f"最近模式: {loop_detected.get('recent_pattern', 'unknown')}"
                )
            else:
                loop_text = "无循环检测"

            # 历史未采纳建议（供 Advisor 自行判断）
            if previous_guidance:
                guidance_text = "\n".join(
                    f"- [{i+1}] {g}" for i, g in enumerate(previous_guidance[-3:])
                )
                guidance_text += f"\n\n**请判断**：根据最近的工具调用（{tools_text}），上述建议是否已被采纳？如果未采纳，请在本次干预中升级语气。"
            else:
                guidance_text = "无历史未采纳建议"

            # 构建侦察缓存上下文（仅当前挑战的缓存）
            recon_context = ""
            challenge_cache = self._get_current_challenge_cache()
            if challenge_cache:
                for stage, data in challenge_cache.items():
                    skills = str(data.get("skills", ""))[:200]
                    recon_context += f"- {stage}: {skills}\n"

            # 根据当前攻击阶段选择动态 prompt
            stage_title, stage_intro, criteria = _STAGE_CRITERIA.get(
                self._current_stage, (
                    "## 任务",
                    "你正在监控 CTF 渗透 Agent 的思考过程。请评估以下最近的思考和操作，判断是否需要干预。",
                    _FULL_CRITERIA,
                )
            )
            prompt = _EVALUATE_BASE_TEMPLATE.format(
                stage_title=stage_title,
                stage_intro=stage_intro,
                criteria_text=criteria,
                thinking_history=thinking_history[-8000:],
                recent_actions=actions_text,
                recent_results=recent_results or "无",
                progress_summary=progress_summary or "无",
                loop_status=loop_text,
                previous_guidance=guidance_text,
                recon_context=recon_context or "暂无侦察信息",
            )

            messages = [
                {"role": "system", "content": ADVISOR_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]

            result = await self._client.call_with_details(
                model=self._model,
                messages=messages,
                temperature=0.1,
                timeout=30,
            )

            if not result.success or not result.content:
                return None, [], False

            parsed = self._parse_json(result.content)
            if not parsed:
                return None, [], False

            unaddressed = parsed.get("unaddressed_guidance", [])
            if not isinstance(unaddressed, list):
                unaddressed = []

            switch_challenge = parsed.get("suggest_challenge_switch", False)

            # 正常干预判断
            if parsed.get("need_intervention") and parsed.get("guidance"):
                guidance = parsed["guidance"].strip()
                if guidance:
                    if unaddressed:
                        unaddressed_text = "\n仍未解决的历史问题: " + "; ".join(unaddressed[:3])
                        guidance += unaddressed_text
                    logger.info(f"[Advisor] Intervention: {parsed.get('reason', '')}")
                    return guidance, unaddressed, switch_challenge

            # 没有干预但有需要跟踪的建议，也返回（作为温和提醒）
            if unaddressed and parsed.get("guidance"):
                guidance = parsed["guidance"].strip()
                if guidance:
                    unaddressed_text = "\n历史未决问题: " + "; ".join(unaddressed[:3])
                    guidance += unaddressed_text
                    logger.info(f"[Advisor] Follow-up: {parsed.get('reason', '')}")
                    return guidance, unaddressed, switch_challenge

            # 强制最大干预间隔：超过 6 轮未干预，返回强制进度确认
            if turns_since_last_intervention >= 6:
                reason = parsed.get("reason", "常规进度检查")
                next_steps = parsed.get("predicted_next_steps", [])
                steps_text = ""
                if next_steps:
                    steps_text = "\n建议后续步骤: " + " -> ".join(next_steps[:3])
                check_msg = f"[ADVISOR_CHECK] {reason}{steps_text}。请回应你的判断。"
                logger.info(f"[Advisor] Forced check at turn+{turns_since_last_intervention}")
                return check_msg, unaddressed, switch_challenge

            return None, unaddressed, switch_challenge

        except Exception as e:
            logger.warning(f"[Advisor] Evaluate failed: {e}")
            return None, [], False

    async def compress_conversation(
        self,
        messages: list,
    ) -> Optional[str]:
        """
        语义压缩对话历史，返回进度摘要。

        Args:
            messages: 完整对话历史

        Returns:
            200 字以内的进度摘要，或 None
        """
        try:
            # 构建对话文本，跳过 system 消息中的 [PROGRESS_SUMMARY] 和 [TOKEN]
            parts = []
            for msg in messages:
                content = msg.get("content", "")
                role = msg.get("role", "")
                if role == "system" and ("[PROGRESS_SUMMARY]" in content or "[TOKEN]" in content):
                    continue  # 跳过之前的摘要和 token 统计
                tool_name = ""
                if role == "tool":
                    tool_name = f" [tool_result]"
                elif "tool_calls" in msg:
                    tool_name = f" [tool_calls]"
                preview = content[:500] if len(content) > 500 else content
                parts.append(f"[{role}{tool_name}] {preview}")

            conversation_text = "\n\n".join(parts)

            # 防御性截断：防止压缩调用自身超限
            max_conv_chars = 80000  # 约 20K tokens（Qwen 0.85 系数）
            if len(conversation_text) > max_conv_chars:
                # 保留头部 + 尾部，中间用省略号代替
                head = conversation_text[:max_conv_chars // 2]
                tail = conversation_text[-max_conv_chars // 2:]
                conversation_text = head + "\n\n... [中间部分已省略，重点关注首尾] ...\n\n" + tail
                logger.info(f"[Advisor] Compression input capped at {max_conv_chars} chars")

            prompt = COMPRESS_PROMPT.format(conversation_text=conversation_text)

            messages_for_llm = [
                {"role": "system", "content": "你是一个专业的 CTF 渗透测试进度分析助手。请阅读以下对话，生成精简的进度摘要。"},
                {"role": "user", "content": prompt},
            ]

            result = await self._client.call_with_details(
                model=self._model,
                messages=messages_for_llm,
                temperature=0.1,
                timeout=90,
            )

            if not result.success or not result.content:
                return None

            summary = result.content.strip()
            if not summary:
                return None
            # 硬截断 3000 字符（防止 LLM 不遵守 500 字要求）
            if len(summary) > 3000:
                summary = summary[:3000] + "..."
            self._last_summary = summary
            logger.info(f"[Advisor] Compressed: {len(summary)} chars summary")
            return summary

        except Exception as e:
            logger.warning(f"[Advisor] Compress failed: {e}")
            return None

    # ========================================================================
    # 后台侦察循环
    # ========================================================================

    def start_background_loop(self, messages, mcp_client):
        """启动后台侦察循环（非阻塞）"""
        if self._running:
            return
        self._running = True
        self._last_messages_len = len(messages)
        self._background_task = asyncio.create_task(
            self._background_loop(messages, mcp_client)
        )
        logger.info("[Advisor] Background recon loop started")

    def stop_background_loop(self):
        """停止后台侦察循环"""
        self._running = False
        if self._background_task and not self._background_task.done():
            self._background_task.cancel()
        if self._recon_task and not self._recon_task.done():
            self._recon_task.cancel()
        logger.info("[Advisor] Background recon loop stopped")

    async def _background_loop(self, messages, mcp_client):
        """后台实时循环：每 8 秒做一次 LLM 评估，平衡 API 消耗和响应速度"""
        while self._running:
            await asyncio.sleep(8)

            # 正在处理中 → 跳过
            if self._processing:
                continue

            # 无新消息 → 跳过评估
            if len(messages) <= self._last_messages_len:
                continue

            self._processing = True
            try:
                recent = messages[-10:]  # 只看最近 10 条

                # LLM 评估
                assessment = await self._run_assessment(recent)
                if not assessment:
                    self._last_messages_len = len(messages)
                    continue

                current = assessment.get("current_stage", "")
                predicted = assessment.get("predicted_next")
                need_recon = assessment.get("need_recon", False)
                recon_query = assessment.get("recon_query", "")
                prediction_match = assessment.get("prediction_match", "")

                # 决策 1：需要侦察 → 启动侦察任务
                if need_recon and recon_query and predicted:
                    if self._recon_task and not self._recon_task.done():
                        self._recon_task.cancel()
                    self._predicted_stage = predicted
                    self._recon_task = asyncio.create_task(
                        self._run_recon(predicted, recon_query, mcp_client)
                    )

                # 决策 2：预测确认/正确 → 注入侦察结果
                if prediction_match in ("correct", "confirmed") and self._predicted_stage:
                    challenge_cache = self._get_current_challenge_cache()
                    recon_data = challenge_cache.get(self._predicted_stage) if challenge_cache else None
                    if recon_data:
                        self._inject_recon(messages, self._predicted_stage, recon_data)
                        self._predicted_stage = None

                # 决策 3：预测变了 → 重置
                if prediction_match == "changed":
                    self._predicted_stage = None
                    if self._recon_task and not self._recon_task.done():
                        self._recon_task.cancel()

                self._last_messages_len = len(messages)

            except asyncio.CancelledError:
                break
            finally:
                self._processing = False

    async def _run_assessment(self, recent_messages: list) -> Optional[Dict]:
        """LLM 轻量评估：判断当前阶段、预测下一步"""
        try:
            # 格式化最近 10 条完整思考过程
            parts = []
            # 收集最近 5 次工具调用
            tool_calls_parts = []
            tool_call_count = 0

            for msg in recent_messages:
                role = msg.get("role", "")
                content = msg.get("content", "")

                # 完整思考内容（最多 500 字符）
                if content:
                    parts.append(f"[{role}] {content[:500]}")

                # 工具调用（同时保留思考和工具调用）
                if "tool_calls" in msg:
                    tcs = msg.get("tool_calls", [])
                    for tc in tcs:
                        func = tc.get("function", {})
                        name = func.get("name", "")
                        args = func.get("arguments", "{}")
                        if tool_call_count < 5:
                            tool_calls_parts.append(f"[TOOL_CALL] {name}({args[:200]})")
                            tool_call_count += 1

                # tool 执行结果
                elif role == "tool":
                    preview = content[:300] if len(content) > 300 else content
                    parts.append(f"[tool_result] {preview}")

            messages_text = "\n".join(parts) if parts else "无"
            tools_text = "\n".join(tool_calls_parts) if tool_calls_parts else "无"

            # 上次预测
            if self._predicted_stage:
                last_pred = f"上次预测阶段: {self._predicted_stage}"
            else:
                last_pred = "无（首次评估）"

            # 侦察缓存摘要（仅当前挑战的缓存）
            challenge_cache = self._get_current_challenge_cache()
            if challenge_cache:
                recon_parts = []
                for stage, data in challenge_cache.items():
                    skills = str(data.get("skills", ""))[:150]
                    recon_parts.append(f"- {stage}: {skills}")
                recon_cache_text = "\n".join(recon_parts)
            else:
                recon_cache_text = "暂无侦察缓存"

            prompt = ASSESSMENT_PROMPT.format(
                recent_messages=messages_text,
                recent_tools=tools_text,
                last_prediction=last_pred,
                recon_cache=recon_cache_text,
            )

            messages = [
                {"role": "system", "content": "你是 CTF 渗透任务的状态分析器。只输出 JSON，不要多余文字。"},
                {"role": "user", "content": prompt},
            ]

            result = await self._client.call_with_details(
                model=self._model,
                messages=messages,
                temperature=0.1,
                timeout=20,
            )

            if not result.success or not result.content:
                self._current_stage = None  # 失败时清除过期 stage
                return None

            parsed = self._parse_json(result.content)
            if parsed:
                # 存储当前阶段，供 evaluate() 使用动态 prompt
                self._current_stage = parsed.get("current_stage")
                logger.info(
                    f"[Advisor] Assessment: stage={parsed.get('current_stage')} "
                    f"→ predicted={parsed.get('predicted_next')} "
                    f"match={parsed.get('prediction_match')}"
                )
            else:
                self._current_stage = None  # 解析失败也清除
            return parsed

        except Exception as e:
            logger.debug(f"[Advisor] Assessment failed: {e}")
            return None

    async def _run_recon(self, stage: str, query: str, mcp_client):
        """执行侦察：搜索相关 skill、模板等资源（按 challenge code 隔离）"""
        try:
            recon_data = {}
            challenge_code = self._current_recon_challenge_code or "_default_"

            # 侦察 1: search_skills
            await asyncio.sleep(0.5)  # API 限频间隔
            try:
                result = await mcp_client.call_tool("kali", "search_skills", {"query": query})
                recon_data["skills"] = str(result)[:2000]
            except Exception as e:
                recon_data["skills"] = f"search_skills failed: {e}"

            # 侦察 2: list_skills（完整列表）
            await asyncio.sleep(0.5)
            try:
                result = await mcp_client.call_tool("kali", "list_skills", {})
                recon_data["all_skills"] = str(result)[:1500]
            except Exception as e:
                recon_data["all_skills"] = f"list_skills failed: {e}"

            # 缓存到当前挑战的 stage 下
            self._recon_cache.setdefault(challenge_code, {})[stage] = recon_data
            logger.info(f"[Advisor] Recon complete for challenge={challenge_code}, stage={stage}")

        except asyncio.CancelledError:
            logger.info(f"[Advisor] Recon cancelled for stage: {stage}")
        except Exception as e:
            logger.warning(f"[Advisor] Recon failed for {stage}: {e}")

    def _inject_recon(self, messages, stage: str, recon_data: Dict):
        """将侦察结果注入到 messages"""
        parts = []
        if recon_data.get("skills"):
            parts.append(f"## 相关 Skill\n{recon_data['skills']}")
        if recon_data.get("all_skills"):
            parts.append(f"## 完整 Skill 列表（节选）\n{recon_data['all_skills']}")

        if not parts:
            return

        recon_text = f"[RECON] {stage} 阶段可用资源已就绪：\n\n" + "\n\n".join(parts)
        messages.append({"role": "system", "content": recon_text})
        logger.info(f"[Advisor] Injected RECON for stage: {stage}")

    def analyze_failure(
        self,
        tool_name: str,
        arguments: dict,
        result: str,
        messages: list,
    ) -> Optional[str]:
        """
        分析失败原因，从历史消息中提取相关上下文。

        这是纯本地分析，不消耗 LLM 调用。
        """
        hints = []
        result_lower = result.lower()

        # 权限类失败
        if "permission denied" in result_lower or "forbidden" in result_lower:
            # 从历史中提取 whoami / sudo -l 结果
            for msg in messages:
                content = msg.get("content", "")
                if "sudo -l" in content and ("NOPASSWD" in content or "ALL" in content):
                    hints.append(f"历史中发现 sudo 权限信息，请检查是否有可用的提权路径")
                    break
                if "uid=" in content or "www-data" in content or "root" in content:
                    hints.append(f"历史中有关于当前用户的信息，请确认是否已检查 sudo 权限")
                    break

        # 连接类失败
        if "connection refused" in result_lower or "timed out" in result_lower:
            hints.append("连接失败。确认目标服务是否正常运行，网络是否可达。")

        # 未找到类
        if "not found" in result_lower or "no such" in result_lower:
            hints.append("目标不存在。确认路径/URL 是否正确，或是否需要先创建。")

        # 返回建议
        if hints:
            return "\n".join(hints)
        return None

    def _parse_json(self, text: str) -> Optional[Dict]:
        """容错解析 LLM JSON 输出"""
        text = text.strip()

        # 尝试直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 尝试提取 ```json 块
        match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # 尝试提取 { ... } 块：从第一个 { 到最后一个 }（贪婪匹配完整 JSON）
        first = text.find('{')
        last = text.rfind('}')
        if first != -1 and last > first:
            candidate = text[first:last + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        logger.warning(f"[Advisor] JSON parse failed for: {text[:100]}")
        return None


__all__ = ["CTFAdvisor"]
