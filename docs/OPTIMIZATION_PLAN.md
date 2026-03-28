# CTF-Agent 框架优化修复计划 V2

## 一、修复目标

1. **剪除硬编码**：移除干扰AI自主判断的硬编码逻辑
2. **增强场景推理**：为AI提供判断依据而非直接答案
3. **优化知识库检索**：在合适的时机检索合适的内容
4. **提升上下文传递**：实现知识的有效累积

---

## 二、修改文件清单

### 2.1 新增文件

| 文件 | 内容 | 负责Agent |
|------|------|-----------|
| `tools/tool_scenarios.py` | 工具场景知识库定义 | Agent-1 |

### 2.2 修改文件

| 文件 | 修改类型 | 负责Agent |
|------|---------|-----------|
| `tools/tool_framework.py` | 增加：工具信息输出增强 | Agent-1 |
| `app/tool_selector.py` | 删除+修改：删除硬编码映射，简化函数 | Agent-2 |
| `app/ctf_agent_graph.py` | 删除+增加：删除硬编码扫描，增加检索 | Agent-3 |
| `app/attacker_prompt.py` | 删除+增加+修改：优化提示词和截断 | Agent-4 |
| `app/analyst_prompt.py` | 增加：场景识别引导 | Agent-5 |

### 2.3 审查任务

| 范围 | 内容 | 负责Agent |
|------|------|-----------|
| 全项目 | 老旧代码、语法规范、注释合理 | Agent-6 |

---

## 三、详细修改规范

### 3.1 Agent-1: 工具场景定义

**新建**: `tools/tool_scenarios.py`

要求：
- 定义所有工具的场景说明
- 每个工具包含: function, best_for(3-5条), not_for(2-3条), prerequisite, cost, example
- 覆盖工具: nuclei, dirsearch, sqlmap, ffuf, requests, python-exec, fenjing, xxe-injector, ssrfmap, ssrf-scanner, phpggc, ysoserial, marshalsec, jndi-exploit, jwt-tool, flask-unsign, gopherus, httpx, subfinder, oa-exploiter, cve-scanner, pickle-pwn, file-creator, python-exec, dalfox

**修改**: `tools/tool_framework.py`

要求：
- get_all_tools_info() 方法导入并输出场景说明
- 格式清晰，便于AI理解

### 3.2 Agent-2: 工具选择器简化

**修改**: `app/tool_selector.py`

删除：
- TOOL_MAPPING 字典
- VULN_TO_TOOLS 字典
- TOOL_PRESETS 中硬编码预设
- get_tool_recommendation 中的硬编码逻辑

修改：
- select_tools() 只返回可用工具列表，不做优先级排序
- 保留 VulnCategory 枚举和 ToolRecommendation 类

### 3.3 Agent-3: 图节点优化

**修改**: `app/ctf_agent_graph.py`

删除：
- 侦察阶段硬编码 scan_tools 调用
- attacker_node 中并行扫描的硬编码逻辑
- 超时硬编码（改为从场景获取或默认值）

增加：
- analyst_node: 识别漏洞后检索payloads（top_k=3）
- attacker_node: 攻击前检索nuclei模板（有CVE时）和payloads
- verifier_node: 尝试3次后检索writeups和security_resources

### 3.4 Agent-4: 攻击提示词优化

**修改**: `app/attacker_prompt.py`

删除：
- 硬编码工具引导 "优先使用recommended_tools"

修改：
- smart_truncate_output(): 默认800字符，代码类扩大3倍

增加：
- 场景推理框架（代码审计/CVE利用/逻辑绕过/黑盒测试）
- 工具选择原则（最小成本、精确优于批量、验证优于假设）
- 不误导AI的合理引导

### 3.5 Agent-5: 分析提示词增强

**修改**: `app/analyst_prompt.py`

增加：
- 场景类型判断引导
- 四种场景特征说明（代码审计/CVE利用/逻辑绕过/黑盒测试）
- 场景→策略映射原则

### 3.6 Agent-6: 全项目审查

审查项：
1. 搜索残留的 TOOL_MAPPING、VULN_TO_TOOLS 引用
2. 搜索硬编码 nuclei、dirsearch 调用位置
3. 检查导入语句规范
4. 检查函数签名一致性
5. 检查注释合理性

---

## 四、知识库检索时机

| 节点 | 时机 | 检索源 | 目的 |
|------|------|--------|------|
| analyst_node | 识别漏洞类型后 | payloads | 获取payload参考 |
| attacker_node | 有CVE编号时 | nuclei | 获取模板 |
| attacker_node | 生成攻击动作前 | payloads | 获取利用方法 |
| verifier_node | 连续失败3次后 | writeups, security_resources | 获取思路 |

---

## 五、检查清单

### 5.1 功能检查
- [ ] 所有工具都有场景说明
- [ ] 场景说明覆盖best_for和not_for
- [ ] 知识库检索时机正确
- [ ] 状态传递完整

### 5.2 代码规范检查
- [ ] 无硬编码工具映射
- [ ] 无硬编码扫描调用
- [ ] 导入路径正确
- [ ] 函数签名一致

### 5.3 AI引导检查
- [ ] 引导不包含硬性规定
- [ ] 引导给出判断依据
- [ ] 引导不误导AI

---

## 六、执行计划

1. 并行启动 Agent-1 至 Agent-5 执行各自修改任务
2. 等待所有Agent完成后，启动 Agent-6 进行全项目审查
3. 汇总结果，进行最终验证