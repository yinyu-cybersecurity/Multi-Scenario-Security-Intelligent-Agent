# CTF-Agent 项目配置

## 项目概述

CTF-Agent 是一个基于 LangGraph 的智能 CTF 自动化求解框架，支持 Web、Pwn、Crypto、Reverse、Misc、内网渗透、云安全、AI安全等 8 个 CTF 方向。

**当前版本**: 2.0  
**架构基座**: Claude Code CLI + LangGraph

---

## 核心架构

### Agent 类型系统

| Agent类型 | 模型 | 权限 | 用途 |
|-----------|------|------|------|
| Explore | glm-5 | 只读 | 代码探索、信息收集 |
| Plan | glm-5 | 只读 | 攻击策略规划 |
| Attack | glm-5 | 读写执行 | 漏洞利用执行 |
| Verify | glm-5 | 读写执行 | 结果验证、对抗测试 |

### 状态机流程

```
ChallengeDetection → Explore → Plan → Attack → Verify → [Flag Found?]
                                                    ↓
                                              Evolve → Plan
```

---

## 工具框架

### buildTool 工厂模式

```python
from app.tools.tool_factory import buildTool

# 创建工具示例
sqlmap_tool = buildTool(
    name="sqlmap",
    description="SQL注入自动化利用工具",
    parameters={
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "format": "uri"},
            "level": {"type": "integer", "minimum": 1, "maximum": 5}
        },
        "required": ["target_url"]
    },
    handler=sqlmap_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK]
)
```

### 权限检查

```python
# Agent层权限限制
- Explore: 仅 Read, Glob, Grep, LSP, WebFetch
- Plan: Read, Glob, Grep, AskUserQuestion
- Attack: Read, Write, Edit, Bash, MCP工具
- Verify: Read, Bash, Semgrep扫描
```

---

## MCP 插件配置

### 已启用插件

| 插件 | 功能 | CTF场景 |
|------|------|---------|
| serena | LSP代码分析 | 代码审计、漏洞定位 |
| semgrep-plugin | 静态代码扫描 | 漏洞模式匹配 |
| context7 | 文档查询 | POC查询、技术文档 |
| playwright | 浏览器自动化 | XSS/CSRF测试 |
| chrome-devtools-mcp | 浏览器调试 | 前端漏洞利用 |

### MCP工具调用示例

```python
# 通过MCP调用Semgrep扫描
result = await mcp_manager.execute_tool(
    "mcp__plugin_semgrep-plugin_semgrep__semgrep_scan",
    {"code_files": [{"path": "/app/vulnerable.py"}]},
    agent_type="explore"
)
```

---

## 代码规范

### 安全约束

1. **禁止硬编码敏感信息**: API Key、密码等必须从环境变量读取
2. **命令注入防护**: 所有用户输入必须经过验证
3. **权限分离**: 敏感操作需要 Attack Agent 权限
4. **超时控制**: 所有工具调用设置合理超时

### 错误处理

```python
from app.tools.tool_factory import ensure_result_format

def tool_handler(params: Dict, context: Dict) -> Dict:
    try:
        # 执行逻辑
        result = do_something(params)
        return ensure_result_format({
            "success": True,
            "data": result
        })
    except Exception as e:
        return ensure_result_format({
            "success": False,
            "error": str(e)
        })
```

---

## 目录结构

```
app/
├── agents/           # Agent实现
│   ├── base_agent.py
│   ├── explore_agent.py
│   ├── plan_agent.py
│   ├── attack_agent.py
│   └── verify_agent.py
├── tools/            # 工具系统
│   ├── tool_factory.py
│   ├── schema_validator.py
│   └── permission_checker.py
├── mcp/              # MCP集成
│   ├── mcp_manager.py
│   └── tool_mappings.py
├── graph/            # 状态机
│   ├── ctf_graph_v3.py
│   └── state_v3.py
├── state_types/      # 状态类型定义
├── nodes/            # 节点实现
└── prompts/          # Prompt模板
```

---

## 开发指南

### 添加新工具

1. 在 `app/tools/` 创建工具类继承 `CTFTool`
2. 实现 `execute()`, `check_available()`, `expected_params()`
3. 使用 `@zod_validate` 装饰器添加参数验证
4. 在 `ToolRegistry` 注册工具

### 添加新Agent类型

1. 在 `app/agents/` 创建新Agent类
2. 继承 `BaseAgent` 并配置权限
3. 在 `settings.local.json` 添加Agent配置
4. 更新状态机流程图

### 添加新MCP插件

1. 在 `settings.local.json` 添加MCP配置
2. 在 `mcp/tool_mappings.py` 添加工具映射
3. 更新权限检查器支持新工具

---

## 配置文件

- `.claude/settings.local.json` - Claude Code 配置
- `config.yaml` - 运行时配置
- `app/config.py` - 配置加载器

---

## 相关文档

- [深度重构设计文档](docs/superpowers/specs/2026-04-01-ctf-agent-refactor-design.md)
- [Agent系统技术文档](Agent系统深度技术文档.md)
- [工具系统技术文档](工具系统深度技术文档.md)
- [MCP与扩展系统技术文档](MCP与扩展系统深度技术文档.md)