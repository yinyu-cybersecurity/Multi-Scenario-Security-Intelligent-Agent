# -*- coding: utf-8 -*-
"""
场景框架共享常量

提取自 analyst_prompt.py 和 attacker_prompt.py 的共享内容
用于减少代码重复，统一管理场景识别和策略映射
"""

from typing import Dict, List

# =============================================================================
# 场景识别框架
# =============================================================================

SCENE_FRAMEWORK = """
## 场景推理框架

在生成攻击动作前，请判断当前属于哪种场景：

### 1. 代码审计场景
特征：响应中包含源码、敏感函数调用、过滤逻辑
策略：理解代码逻辑→精确构造payload
工具倾向：requests, python-exec

### 2. CVE利用场景
特征：已知框架版本、已知CVE编号
策略：匹配利用模板→执行攻击
工具倾向：nuclei, ysoserial等

### 3. 逻辑绕过场景
特征：存在验证逻辑、参数过滤、白名单限制
策略：分析限制→构造绕过
工具倾向：requests, python-exec

### 4. 黑盒测试场景
特征：无源码、需要枚举发现
策略：扩大攻击面→验证利用
工具倾向：dirsearch, ffuf, sqlmap
"""

# 详细版场景识别（用于分析师）
SCENE_RECOGNITION_DETAIL = """
## 场景识别

分析漏洞前，请先判断当前属于哪种场景：

### 代码审计场景
识别特征：
- 响应中包含PHP/Java/Python源码
- 存在敏感函数调用(include, eval, system, exec等)
- 有过滤逻辑需要绕过

场景特点：需要人工理解代码逻辑，而非批量扫描
工具选择提示：优先使用灵活的手工测试工具，根据代码逻辑定制攻击方案

### CVE利用场景
识别特征：
- 已知框架版本(如Tomcat 7.0.x, Spring 4.x)
- 已知CVE编号
- 标准化的漏洞模式

场景特点：有现成的利用模板可用
工具选择提示：根据目标框架选择对应的扫描和利用工具

### 逻辑绕过场景
识别特征：
- 存在Cookie/Session验证逻辑
- 存在参数过滤或WAF
- 存在白名单限制

场景特点：需要精确构造绕过payload
工具选择提示：使用精确控制请求的工具，手工构造绕过逻辑

### 黑盒测试场景
识别特征：
- 无源码暴露
- 无明显漏洞特征
- 需要枚举发现攻击面

场景特点：需要扩大攻击面
工具选择提示：使用枚举和扫描工具发现更多攻击路径
"""

# =============================================================================
# 场景到策略的映射
# =============================================================================

SCENE_STRATEGY_MAPPING = """
## 场景→策略映射

根据识别的场景，在漏洞候选中添加recommended_tools时请遵循：
- 代码审计场景：优先推荐requests、python-exec
- CVE利用场景：推荐对应框架的扫描和利用工具
- 逻辑绕过场景：优先推荐精确构造工具
- 黑盒测试场景：推荐枚举和扫描工具
"""

# 场景到工具的映射表（程序化使用）
SCENE_TOOL_MAPPING: Dict[str, List[str]] = {
    "code_audit": ["requests", "python-exec"],
    "cve_exploit": ["nuclei", "ysoserial", "requests"],
    "logic_bypass": ["requests", "python-exec"],
    "blackbox": ["dirsearch", "ffuf", "sqlmap", "requests"],
}

# =============================================================================
# 编码处理提示
# =============================================================================

ENCODING_TIPS = """
涉及精确计算的场景必须使用 `python-exec` 工具写脚本执行，不要自己猜测：

1. **编码解码**: base64、URL编码、十六进制、Unicode、ROT13等
   ```json
   {"tool": "python-exec", "params": {"code": "import base64; result = base64.b64decode('XXXXX').decode()", "description": "base64解码"}}
   ```

2. **加密解密**: MD5、SHA、AES等哈希或加密操作


**错误示例** : 看到 base64 就直接脑补解码结果
**正确示例** : 用 python-exec 写脚本精确解码
"""

# =============================================================================
# 新路径发现提示
# =============================================================================

NEW_PATH_DISCOVERY_TIPS = """
## 关键提示：发现新路径立即访问！

当解码或分析结果中**发现新的文件路径**时（如 `/test2222222222222222.php`）：
1. **立即用 requests 工具直接访问该URL**
2. URL格式: `http://目标域名/新路径`
3. **不要继续证明漏洞存在**，去新路径寻找FLAG！

示例：
```json
{"tool": "requests", "params": {"method": "GET", "url": "http://node7.anna.nssctf.cn:22856/test2222222222222222.php"}, "reasoning": "访问新发现的路径"}
```
"""

# =============================================================================
# 成功判断标准
# =============================================================================

SUCCESS_CRITERIA = """
### 成功程度 (failure_severity)
- **0.0**: 找到FLAG或明确成功（如完整读取到/etc/passwd内容、执行命令返回完整结果）
- **0.3**: 有明显实质进展（上传成功、发现新文件路径、绕过过滤成功且获得有效输出）
- **0.5**: 有变化但无实质价值（响应变化但只是错误信息、被过滤的回显）
- **0.8**: 完全失败（403/404/500/被过滤/无变化）

### 重要：is_exploit_successful 判断标准
**只有满足以下条件之一才能设为true：**
1. 找到FLAG
2. 成功读取到敏感文件内容（如flag.php源码、/etc/passwd完整内容）
3. 命令执行返回完整、有用的输出（不只是"Array"或截断内容）
4. 发现并成功访问新路径，且新路径有可利用内容

**以下情况必须设为false：**
- 响应只是"Array"或截断输出
- 只显示"有变化"但没有获取到实际内容
- 被过滤系统拦截（如"fxck your symbol"）
- 重复使用相同绕过技术
"""

# =============================================================================
# 工具选择原则
# =============================================================================

TOOL_SELECTION_PRINCIPLES = """
## 工具选择原则

1. **最小成本**：低成本低成本工具优先
   - requests (1秒) < python-exec (1秒) < ffuf (数十秒) < dirsearch (数分钟)

2. **精确优于批量**：有明确目标时，直接精确测试

3. **验证优于假设**：每次攻击后验证，根据结果调整
"""

# =============================================================================
# 攻击决策原则（用于分析师）
# =============================================================================

ATTACK_DECISION_PRINCIPLES = """
## 攻击决策原则

1. **场景绑定原则**: 已识别的框架/中间件/技术栈是最高优先级的攻击方向
   - 即使自动化工具扫描无结果，仍需深入测试该场景的所有攻击面
   - 一次漏扫失败不代表目标安全，可能是工具模板不覆盖

2. **深度挖掘思维**: 对已识别的场景，系统性思考可能的漏洞：
   - 该框架/中间件历史上有哪些著名漏洞？
   - 该技术栈常见的配置错误有哪些？
   - 该环境暴露了哪些可利用的功能点？
   - 是否存在绕过检测的可能？

3. **工具是辅助**: 漏扫工具只能发现"有模板的漏洞"，更多漏洞需要手工构造Payload
"""

# =============================================================================
# 组合函数
# =============================================================================

def get_scene_framework_for_attacker(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取攻击兵用的场景框架（简洁版）"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        # 构建战略上下文（使用正确的字段）
        attack_chain = strategic_context.get('attack_chain', [])
        current_step = strategic_context.get('current_step', 0)
        total_steps = strategic_context.get('total_steps', 0)
        blockers = strategic_context.get('blockers', [])
        alternate_routes = strategic_context.get('alternate_routes', [])

        stage_section += f"""
### 战略上下文
- 攻击链进度: 第{current_step}步/共{total_steps}步
- 当前障碍: {', '.join(blockers) if blockers else '无'}
- 备选路径: {', '.join(alternate_routes[:3]) if alternate_routes else '无'}
"""
    return stage_section + SCENE_FRAMEWORK

def get_scene_framework_for_analyst(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取分析师用的场景框架（详细版+策略映射）"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        attack_chain = strategic_context.get('attack_chain', [])
        current_step = strategic_context.get('current_step', 0)
        total_steps = strategic_context.get('total_steps', 0)
        primary_goal = strategic_context.get('primary_goal', '')
        blockers = strategic_context.get('blockers', [])

        stage_section += f"""
### 战略上下文
- 主要目标: {primary_goal}
- 攻击链: {' -> '.join(attack_chain[:5]) if attack_chain else '待规划'}
- 进度: 第{current_step}步/共{total_steps}步
- 当前障碍: {', '.join(blockers) if blockers else '无'}
"""
    return stage_section + SCENE_RECOGNITION_DETAIL + "\n" + SCENE_STRATEGY_MAPPING

def get_encoding_tips(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取编码处理提示"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        blockers = strategic_context.get('blockers', [])
        stage_section += f"""
### 当前障碍: {', '.join(blockers[:3]) if blockers else '无'}
"""
    return stage_section + ENCODING_TIPS

def get_new_path_discovery_tips(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取新路径发现提示"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        alternate_routes = strategic_context.get('alternate_routes', [])
        stage_section += f"""
### 备选路径: {', '.join(alternate_routes[:3]) if alternate_routes else '待发现'}
"""
    return stage_section + NEW_PATH_DISCOVERY_TIPS

def get_success_criteria(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取成功判断标准"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        current_step = strategic_context.get('current_step', 0)
        total_steps = strategic_context.get('total_steps', 0)
        stage_section += f"""
### 进度: 第{current_step}步/共{total_steps}步
"""
    return stage_section + SUCCESS_CRITERIA

def get_tool_selection_principles(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取工具选择原则"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        blockers = strategic_context.get('blockers', [])
        stage_section += f"""
### 当前障碍: {', '.join(blockers[:3]) if blockers else '无'}
"""
    return stage_section + TOOL_SELECTION_PRINCIPLES

def get_attack_decision_principles(stage_info: Dict = None, strategic_context: Dict = None) -> str:
    """获取攻击决策原则"""
    stage_section = ""
    if stage_info:
        stage_section = f"""
## 当前阶段: {stage_info.get('stage_name', '')}
### 阶段目标: {stage_info.get('goal', '')}
"""
    if strategic_context:
        primary_goal = strategic_context.get('primary_goal', '')
        stage_section += f"""
### 主要目标: {primary_goal}
"""
    return stage_section + ATTACK_DECISION_PRINCIPLES

def get_recommended_tools(scene_type: str) -> List[str]:
    """根据场景类型获取推荐工具列表"""
    return SCENE_TOOL_MAPPING.get(scene_type, ["requests"])