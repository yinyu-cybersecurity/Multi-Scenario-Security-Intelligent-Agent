# CTF-Agent 2.0

基于 Claude Code 架构的智能 CTF 自动化求解框架。

**核心理念**: 框架做得越少越好，AI做得越多越好

## 特性

- **极简架构**: 1个MCP服务器，12个工具
- **完全操控**: AI可调用Kali Linux 300+安全工具
- **技能系统**: 115个攻击技能
- **比赛适配**: 内置CTF比赛工具链

## 快速开始

### 方式一：Kali虚拟机直接运行（推荐）

```bash
# 复制项目到Kali后进入目录
cd ctf-agent

# 直接运行（自动创建虚拟环境）
chmod +x run_kali.sh
./run_kali.sh http://target.com

# 比赛模式
./run_kali.sh http://target.com competition.host.com your-token
```

首次运行会自动创建虚拟环境并安装依赖。

### 方式二：Docker部署

```bash
./run.sh http://target.com
```

### 配置

编辑 `settings.json`：

```json
{
  "model": {
    "name": "qwen3.5-plus",
    "base_url": "https://coding.dashscope.aliyuncs.com/v1",
    "api_key": "your-api-key"
  }
}
```

## 工具列表

### 基础能力（6个）

| 工具 | 功能 |
|------|------|
| bash | 执行任意命令（调用Kali 300+工具） |
| http | HTTP请求 |
| read/write | 文件操作 |
| remember/recall | 记忆系统 |

### 比赛工具（5个）

| 工具 | 功能 |
|------|------|
| list_challenges | 获取题目列表 |
| start_challenge | 启动题目实例 |
| submit_flag | 提交FLAG |
| stop_challenge | 停止题目实例 |
| view_hint | 查看提示 |

### 技能系统（1个）

| 工具 | 功能 |
|------|------|
| search_skills | 搜索攻击技能（sqli/xss/rce等） |

## Kali工具

AI可调用的部分工具：

- **信息收集**: nmap, nuclei, whatweb, subfinder
- **Web安全**: sqlmap, ffuf, dirsearch, nikto
- **密码破解**: hashcat, john, hydra
- **二进制**: binwalk, gdb, radare2
- **漏洞利用**: searchsploit, msfconsole
- **内网渗透**: crackmapexec, impacket

## 目录结构

```
app/
├── core/query.py         # Query循环
├── cli.py                # CLI入口
├── llm_client.py         # LLM调用
└── prompts/              # 系统提示词

mcp_servers/
└── kali_server.py        # 唯一MCP服务器

skills/                   # 115个攻击技能
run_kali.sh               # Kali直接运行脚本
run.sh                    # Docker运行脚本
settings.json
```

## 许可证

MIT License