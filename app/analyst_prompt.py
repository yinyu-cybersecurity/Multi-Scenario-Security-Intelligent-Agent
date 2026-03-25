import json

def get_analyst_prompt(page_features: dict, raw_html: str, rule_candidates: list,
                        task_name: str = "Unknown", task_description: str = "None",
                        baseline_response: dict = None, detected_scenes: dict = None,
                        tools_info: str = None,
                        focused_scene: str = None,
                        scene_tested: bool = False,
                        topology_hint: str = None) -> str:
    """
    生成分析兵的情报统筹提示词。
    """

    # 构建重定向信息
    redirect_info = ""
    if baseline_response:
        final_url = baseline_response.get("final_url", "")
        redirect_chain = baseline_response.get("redirect_chain", [])
        if redirect_chain or (final_url and "?" in final_url):
            redirect_info = f"最终URL: {final_url}\n"
            if "?" in final_url:
                params_part = final_url.split("?", 1)[1]
                redirect_info += f"URL参数: {params_part}\n"

    # 场景信息格式化
    scenes_section = ""
    if detected_scenes:
        scenes_lines = []

        if detected_scenes.get("framework"):
            fw_str = ", ".join([
                f"{fw['name']}" + (f"/{fw['version']}" if fw.get('version') else "")
                for fw in detected_scenes["framework"]
            ])
            scenes_lines.append(f"框架/中间件: {fw_str}")

        if detected_scenes.get("input_vectors"):
            vec_strs = []
            for vec in detected_scenes["input_vectors"]:
                if vec["type"] == "parameter":
                    vec_strs.append(f"{vec.get('method', '')}参数:{vec['name']}")
                elif vec["type"] == "form":
                    vec_strs.append(f"表单:{vec['name']}")
            if vec_strs:
                scenes_lines.append(f"输入向量: {', '.join(vec_strs)}")

        if detected_scenes.get("sensitive_paths"):
            scenes_lines.append(f"敏感路径: {', '.join(detected_scenes['sensitive_paths'][:5])}")

        if detected_scenes.get("data_patterns"):
            pattern_strs = [p.get("hint", p["type"]) for p in detected_scenes["data_patterns"]]
            scenes_lines.append(f"数据特征: {', '.join(pattern_strs)}")

        if detected_scenes.get("hints"):
            scenes_lines.append(f"其他线索: {'; '.join(detected_scenes['hints'][:3])}")

        if scenes_lines:
            scenes_section = "## 检测到的场景\n" + "\n".join(scenes_lines) + "\n"

    # 聚焦场景提示
    focus_section = ""
    if focused_scene and not scene_tested:
        focus_section = f"""
## ⚠️ 重点攻击方向
已识别到 **{focused_scene}**，这是当前最高优先级的攻击目标。
自动化漏扫可能遗漏了该环境的漏洞，请深度挖掘该场景的所有可能攻击面：
- 已知CVE（包括最新公开的漏洞）
- 配置缺陷（默认凭据、未授权访问、错误配置）
- 功能漏洞（文件操作、命令执行、信息泄露）
- 协议/端口层面的攻击
- 组件依赖的漏洞

不要因为漏扫无结果就放弃该方向，尝试手工构造攻击请求。
"""

    # 预格式化JSON（f-string不支持反斜杠）
    page_features_json = json.dumps(page_features, indent=2, ensure_ascii=False)[:1000]
    rule_candidates_json = json.dumps(rule_candidates, indent=2, ensure_ascii=False)[:500]
    topology_section = f"## 拓扑分析\n{topology_hint}\n" if topology_hint else ""

    return f"""
# CTF 分析兵

## 任务
根据侦察数据识别攻击方向，选择合适的工具。

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

## 题目信息
- 名称: {task_name}
- 描述: {task_description}
{redirect_info}

{scenes_section}
{focus_section}
{topology_section}
## 页面特征
{page_features_json}

## 规则引擎预警
{rule_candidates_json}

## 可用工具
{tools_info if tools_info else "见工具列表"}

## 决策要求

1. **场景联想**: 根据检测到的框架/版本，联想该环境可能存在的所有漏洞类型
2. **工具选择**: 选择最适合的工具，如果工具不可用则推荐手工构造
3. **精准定位**: 每个漏洞候选给出具体的攻击位置、Payload思路、预期效果

## 输出格式 (JSON)
```json
{{
  "candidates": [
    {{
      "type": "漏洞类型",
      "location": "具体URL和参数",
      "confidence": 0.85,
      "reason": "判断依据",
      "attack_approach": "攻击思路：如何构造Payload、预期触发什么行为",
      "recommended_tools": ["工具名"],
      "context": {{}}
    }}
  ],
  "key_intel": "关键发现",
  "attack_strategy": "推荐攻击策略：先做什么、后做什么、如果失败如何调整"
}}
```

注意: candidates不能为空，必须给出明确的攻击方向。优先针对已识别的场景给出攻击方案。
"""