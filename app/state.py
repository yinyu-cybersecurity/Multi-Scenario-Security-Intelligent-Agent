# state.py - 核心状态定义
# 创建时间：2026-03-14
# 作用：定义系统的所有数据结构，供其他模块引用

import operator
from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict


# ==============================================================================
# 1. 辅助类型定义
# ==============================================================================

class VulnerabilityCandidate(TypedDict):
    """[分析兵产出] 潜在漏洞点

    这是从页面特征到具体攻击的中间态，分析兵识别出可能存在的漏洞，
    但不生成具体Payload，只指明方向和置信度。

    Attributes:
        type: 漏洞类型, e.g., 'sqli', 'rce', 'lfi', 'xss', 'ssrf'
        location: 漏洞位置, e.g., 'param:id', 'header:User-Agent', 'form:username'
        confidence: 置信度 0-1, 越高越可信
        context: 上下文信息, 如技术栈、参数示例、WAF特征等
        recommended_tools: [工具集成] 推荐使用的工具列表
    """
    type: str
    location: str
    confidence: float
    context: Dict[str, Any]
    recommended_tools: List[str]
    url: str # 明确漏洞归属的 URL

# ==============================================================================
# 0. 状态规约器 (Reducers)
# ==============================================================================

def cap_list_reducer(x: List[Any], y: List[Any], cap: int = 20) -> List[Any]:
    """
    带上限的列表追加规约器。
    x: 现有状态
    y: 新增数据
    cap: 允许保留的最大条目数（默认 20）
    """
    if x is None: x = []
    if y is None: y = []
    # 如果 y 本身就是空的，直接返回 x
    if not y: return x
    
    new_list = x + y
    if len(new_list) > cap:
        return new_list[-cap:]
    return new_list

def cap_results_reducer(x: List[Dict], y: List[Dict]) -> List[Dict]:
    return cap_list_reducer(x, y, cap=20)

def cap_candidates_reducer(x: List[VulnerabilityCandidate], y: List[VulnerabilityCandidate]) -> List[VulnerabilityCandidate]:
    """
    智能漏洞候选项规约器：防止重复追加并保持上限。
    """
    if x is None: x = []
    if y is None: y = []
    if not y: return x
    
    # 使用 location + type 作为唯一键进行去重
    existing_map = {f"{c['location']}_{c['type']}": c for c in x}
    for new_cand in y:
        key = f"{new_cand['location']}_{new_cand['type']}"
        # 如果已存在，则更新（保留最新的 context 和 tactical_guidance）
        if key in existing_map:
            existing_map[key].update(new_cand)
        else:
            existing_map[key] = new_cand
            
    new_list = list(existing_map.values())
    # 保持上限 10 条
    return new_list[-10:] if len(new_list) > 10 else new_list

class AttackAction(TypedDict):
    """[攻击兵产出] 具体攻击动作

    这是漏洞点的具体化，直接对应一次工具调用或Payload发送。
    攻击兵批量生成多个AttackAction，并发执行。

    Attributes:
        id: 动作唯一标识
        tool: 使用的工具名, e.g., 'fenjing', 'sqlmap', 'ysoserial', 'requests'
        target: 目标URL或参数
        payload: 具体Payload内容
        params: 工具参数
        priority: 执行优先级 0-1, 越高越先执行
        timeout: 超时时间(秒)
    """
    id: str
    tool: str
    target: str
    payload: str
    params: Dict[str, Any]
    priority: float
    timeout: int


class PageFeatures(TypedDict):
    """[侦察兵产出] 页面特征向量 - Token压缩90%

    将原始HTML压缩为关键特征，大幅减少Token消耗。
    只保留对漏洞挖掘有用的信息。

    Attributes:
        tech_stack: 技术栈, e.g. ['nginx', 'php', 'laravel', 'vue']
        input_vectors: 可控输入点, e.g. ['get:id', 'post:username', 'cookie:session']
        sensitive_paths: 发现的敏感路径, e.g. ['/admin', '/config', '/.git']
        dom_structure_hash: DOM结构哈希，用于页面去重
        form_structure: 表单结构详情, 包含action, method, inputs等
        scripts: JS文件列表, 可能包含隐藏API
        cookies: Cookie信息
        headers: 响应头, 可能包含版本信息
    """
    tech_stack: List[str]
    input_vectors: List[str]
    sensitive_paths: List[str]
    dom_structure_hash: str
    form_structure: List[Dict[str, Any]]
    scripts: List[str]
    cookies: Dict[str, str]
    headers: Dict[str, str]


class Hint(TypedDict):
    """[分级介入] 提示信息

    记录人类或AI给出的提示，用于后续分析和审计。

    Attributes:
        level: 提示级别 1-轻量, 2-中级, 3-详细
        content: 提示内容
        source: 来源: 'ai' 或 'human'
        timestamp: 时间戳
    """
    level: int
    content: str
    source: Literal['ai', 'human']
    timestamp: float


class ToolCall(TypedDict):
    """[工具调用] 记录工具执行

    记录每次工具调用的详细信息，用于性能分析和问题排查。

    Attributes:
        tool_name: 工具名称
        params: 调用参数
        result: 执行结果
        cached: 是否命中缓存
        duration: 执行耗时(秒)
    """
    tool_name: str
    params: Dict[str, Any]
    result: Any
    cached: bool
    duration: float


class NodeAttackStatus(TypedDict):
    """[节点攻击状态] 用于时间熔断和AI决策

    记录每个被攻击节点的实时状态，防止卡死。

    Attributes:
        status: 当前状态 'active' | 'abandoned' | 'success'
        start_time: 开始攻击时间戳
        last_decision_time: 上次问AI的时间戳
        attempt_count: 已尝试次数
        last_status_codes: 最近几次的状态码
        ai_decision_log: AI的历史决策记录
    """
    status: Literal["active", "abandoned", "success"]
    start_time: float
    last_decision_time: float
    attempt_count: int
    last_status_codes: List[int]
    ai_decision_log: List[Dict[str, Any]]


class CTFState(TypedDict):
    """
    [全局状态机] 系统的"内存" - 增量更新机制

    设计原理:
        - 使用Annotated + operator.add实现列表追加，避免覆盖
        - 所有兵种共享此状态，通过状态机流转
        - 关键字段说明:

    [基础上下文]
        target_url: str  # 初始目标URL,只需要记录一次，不需要追加
        current_url: str  # 当前正在处理的URL，直接进行覆盖
        start_time: float  # 开始时间戳，用于超时判断。初始时设置
        current_round: int  # 当前已执行轮次，防止无限循环，达到MAX_TOTAL_ROUNDS时结束

    [页面感知]
        page_features: PageFeatures  # 特征向量(压缩Token)，每次侦察时覆盖
        raw_html_snippet: str  # 关键HTML片段，仅保留form/script/comment

    [拓扑结构]
        site_topology: Annotated[Dict[str, List[str]], lambda x, y: {**x, **y}]
        # 站点拓扑图，用邻接表（字典）存储，而不是直接用NetworkX
        # 因为LangGraph状态必须可序列化，所以存字典格式
        # 需要图分析时临时转成NetworkX，用完转回字典
        # 每次发现新路径时合并，不会覆盖原有结构

    [记忆与知识]
        visited_fingerprints: Annotated[List[str], operator.add]
        # 页面指纹历史，用于去重。不断增加，限制上限100条

        visited_urls: Annotated[List[str], operator.add]
        # 已访问URL列表，回溯和去重，上限100条

        vuln_candidates: Annotated[List[VulnerabilityCandidate], cap_candidates_reducer]
        # 发现的潜在漏洞，分析兵添加，策略过滤器修改，限制最多10条

        permanent_rules: Annotated[List[Dict], operator.add]
        # [进化闭环] 从成功案例沉淀的规则

        tool_cache: Annotated[Dict[str, Any], lambda x, y: {**x, **y}]
        # 工具执行结果缓存，避免重复扫描。key是工具名+目标+参数的哈希

    [执行流]
        attack_batch: List[AttackAction]  # 当前批次的攻击任务，由攻击兵生成，执行后清空

        attack_results: Annotated[List[Dict], cap_results_reducer]
        # 攻击结果日志，攻击兵每次执行后添加，反思兵读取分析
        # 限制最多 20 条，保留最近的结果

        tool_calls: Annotated[List[ToolCall], operator.add]
        # 工具调用记录，用于性能分析和问题排查，建议限制最多200条

    [决策状态]
        failure_weighted_score: float  # [核心] 动态失败分，决定模式切换。核心决策指标，由核验兵更新
        exploration_rounds: int  # 探索模式已执行轮次，模式决策器读取
        rule_miss_count: int  # 规则引擎连续未命中次数，用于触发创新模式
        execution_steps: int  # 当前题目总执行步数，用于HITL触发
        current_mode: Literal['exploit', 'explore', 'innovate', 'end', 'hitl']  # 当前工作模式，由模式决策器设置

    [分级介入]
        hint_level: int  # 已给的最高提示级别(0-3)，避免重复给同级别提示

        hint_history: Annotated[List[Hint], operator.add]
        # 提示历史记录，用于审计和分析，限制最多20条

        last_intervention_step: int  # 上次介入时的步数，避免重复介入

    [RAG与进化]
        rag_context: List[str]  # RAG检索到的参考知识，每次头脑风暴时更新
        temp_rules: List[Dict]  # 本次运行生成的临时规则，会注入策略过滤器
        success_trace: List[Dict]  # 成功路径回溯，用于规则学习，只保留最后一次
    """

    # --- 基础上下文 ---
    task_name: str # 题目名称
    task_description: str # 题目描述
    target_url: str
    current_url: str
    start_time: float
    current_round: int
    found_flag: bool # 新增字段，标记是否找到flag

    # --- 页面感知 ---
    page_features: PageFeatures
    raw_html_snippet: str
    baseline_response: Dict[str, Any] # 初始页面基准（长度、时间、MD5）
    page_history: Dict[str, Dict[str, Any]] # 页面变更历史记录 {url: {last_file, last_md5, ...}}

  # --- 拓扑结构 ---
    site_topology: Annotated[Dict[str, List[str]], lambda x, y: {**x, **y}]
    node_metadata: Annotated[Dict[str, Dict], lambda x, y: {**x, **y}] # 节点属性持久化
    critical_nodes: List[str]  # 关键节点列表
    attack_paths: List[List[str]]  # 发现的攻击路径

    # --- 记忆与知识 ---
    visited_fingerprints: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]
    visited_urls: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]
    vuln_candidates: Annotated[List[VulnerabilityCandidate], cap_candidates_reducer] # [恢复] 自动去重追加
    permanent_rules: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 50)]
    tool_cache: Annotated[Dict[str, Any], lambda x, y: {**x, **y}]

    # --- 执行流 ---
    attack_batch: List[AttackAction]
    attack_results: Annotated[List[Dict], cap_results_reducer]
    tool_calls: Annotated[List[ToolCall], lambda x, y: cap_list_reducer(x, y, 100)]
    latest_tactical_guidance: Optional[str] # 核验兵生成的最新战术指引，攻击兵消费后清空 [P3合并]
    analyst_intel: Optional[str] # 分析兵提取的关键情报（源码、过滤规则等），供所有兵种共享

    # --- 决策状态 ---
    failure_weighted_score: float
    exploration_rounds: int
    rule_miss_count: int
    execution_steps: int
    current_mode: Literal['exploit', 'explore', 'innovate', 'end', 'hitl']
    node_attack_status: Dict[str, NodeAttackStatus]  # 节点攻击状态记录

    # --- 分级介入 ---
    hint_level: int
    hint_history: Annotated[List[Hint], operator.add]
    last_intervention_step: int

    # --- RAG与进化 ---
    rag_context: List[str]
    temp_rules: List[Dict]
    success_trace: List[Dict]

    # --- 已知事实追踪 ---
    known_facts: str  # [P2简化] 自由文本格式的已知事实，由AI自主归纳更新
    # 示例: "已发现: flag.php在/var/www/html目录, 成功绕过: ${IFS}可用, 过滤: cat/flag/空格被禁"
    failed_payloads: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]  # 失败的payload列表，避免重复执行

    # ==============================================================================
    # 内网渗透扩展字段 (Internal Network Extension)
    # 添加时间：2026-03-22
    # 说明：以下字段用于支持内网渗透场景，不影响现有Web CTF功能
    # ==============================================================================

    # --- 内网发现 ---
    internal_hosts: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 50)]
    # 发现的内网主机列表，每个条目包含: {ip, hostname, os, ports: [{port, service, version}]}
    # 由 nmap_tool 等扫描工具填充

    internal_network_range: str  # 内网网段范围，如 "10.10.10.0/24"
    domain_controller: str  # 域控IP或主机名

    # --- 凭据管理 ---
    credentials: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 30)]
    # 已获取的凭据列表，每个条目包含: {host, username, password, hash, domain, type}
    # type可以是: 'plaintext', 'ntlm', 'kerberos', 'ssh_key'

    # --- 会话管理 ---
    active_sessions: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 10)]
    # 活跃的渗透会话，每个条目包含: {host, session_type, username, shell_type}
    # session_type: 'meterpreter', 'shell', 'winrm', 'ssh'

    # --- AD域信息 ---
    ad_domain: str  # AD域名，如 "corp.local"
    ad_users: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]  # 枚举到的域用户
    ad_groups: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]  # 枚举到的域组
    ad_computers: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]  # 枚举到的域计算机
    ad_trusts: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 10)]  # 域信任关系

    # --- 横向移动 ---
    lateral_movement_paths: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 20)]
    # 横向移动路径，每个条目包含: {source, target, method, credential_used}
    # method: 'psexec', 'wmiexec', 'winrm', 'ssh', 'rdp'

    # --- 内网渗透模式控制 ---
    internal_mode: bool  # 是否处于内网渗透模式
    current_internal_target: str  # 当前内网目标IP/主机名
    pivot_host: str  # 跳板机IP/主机名

    # --- 扫描去重 ---
    scanned_ips: Annotated[List[str], lambda x, y: list(set(x + y))]  # 已扫描的IP列表，防止重复扫描
    scanned_urls: Annotated[List[str], lambda x, y: list(set(x + y))]  # 已扫描的URL列表，防止重复dirsearch

    # ==============================================================================
    # Crypto扩展字段 (Cryptography Extension)
    # 添加时间：2026-03-23
    # 说明：以下字段用于支持密码学挑战，不影响现有功能
    # ==============================================================================

    # --- 加密分析 ---
    crypto_mode: bool  # 是否处于密码学模式
    crypto_analysis: Dict[str, Any]  # 加密分析结果
    identified_ciphertexts: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 20)]
    # 识别出的密文列表

    # --- 解密结果 ---
    decrypted_data: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 20)]
    # 解密结果，每个条目包含: {ciphertext, type, plaintext, method}

    potential_flags: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 10)]
    # 潜在的flag列表

    # --- RSA参数 ---
    rsa_params: Dict[str, Any]  # RSA参数: {n, e, c, p, q, d, phi}
    # 用于RSA相关挑战

    # --- 古典密码 ---
    classical_cipher_hints: List[str]  # 古典密码提示（如密钥长度猜测）

    # ==============================================================================
    # Pwn扩展字段 (Binary Exploitation Extension)
    # 添加时间：2026-03-23
    # ==============================================================================

    # --- Pwn模式控制 ---
    pwn_mode: bool  # 是否处于Pwn模式
    binary_path: str  # 二进制文件路径

    # --- 二进制分析 ---
    binary_info: Dict[str, Any]  # 二进制信息: {arch, bits, protections, functions}
    vulnerabilities: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 20)]
    # 检测到的漏洞列表
    pwn_analysis: Dict[str, Any]  # Pwn分析结果: {status, arch, protections, llm_insight}

    # --- Exploit构建 ---
    exploit_script: str  # 生成的exploit脚本
    exploit_info: Dict[str, Any]  # exploit详细信息

    # ==============================================================================
    # Reverse扩展字段 (Reverse Engineering Extension)
    # 添加时间：2026-03-23
    # ==============================================================================

    # --- 逆向模式控制 ---
    reverse_mode: bool  # 是否处于逆向模式
    reverse_info: Dict[str, Any]  # 逆向分析信息

    # --- 反编译结果 ---
    decompiled_code: str  # 反编译代码
    algorithm_type: str  # 识别的算法类型
    key_findings: str  # 关键发现

    # --- 函数分析 ---
    functions: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]
    extracted_strings: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]

    # ==============================================================================
    # Misc扩展字段 (Miscellaneous Extension)
    # 添加时间：2026-03-23
    # ==============================================================================

    # --- Misc模式控制 ---
    misc_mode: bool  # 是否处于Misc模式
    misc_file: str  # Misc文件路径

    # --- 文件分析 ---
    file_info: Dict[str, Any]  # 文件信息
    steg_results: Dict[str, Any]  # 隐写术检测结果
    media_analysis: Dict[str, Any]  # 媒体分析结果
    misc_analysis: Dict[str, Any]  # Misc分析结果: {status, findings, llm_insight}

    # --- 数据提取 ---
    extracted_data: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 20)]
    embedded_files: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 10)]

    # --- 附件管理 ---
    attachments: List[Dict[str, Any]]  # 挑战附件列表


# ==============================================================================
# 内网渗透辅助数据结构
# ==============================================================================

class InternalHost(TypedDict):
    """内网主机信息"""
    ip: str
    hostname: str
    os: str
    ports: List[Dict]  # [{port, protocol, service, version, state}]
    domain: str  # 所属域
    is_dc: bool  # 是否是域控


class Credential(TypedDict):
    """凭据信息"""
    host: str
    username: str
    password: Optional[str]
    hash: Optional[str]  # NTLM: LMHASH:NTHASH
    domain: Optional[str]
    cred_type: Literal['plaintext', 'ntlm', 'kerberos', 'ssh_key', 'password_hash']


class LateralMove(TypedDict):
    """横向移动记录"""
    source_host: str
    target_host: str
    method: str  # psexec, wmiexec, ssh, etc.
    credential_used: str  # username@domain
    success: bool
    timestamp: float