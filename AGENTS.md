# AGENTS.md

## 目的

本文件给参与本仓库的开发者、审阅者与自动化 Agent 提供统一的协作约束。重点不是重复 README，而是说明：

- 这个仓库的真实风险面在哪里
- 改动前后最低限度要做哪些验证
- GitHub 协作时必须遵守什么规范

---

## 仓库概览

- 项目类型：基于 LangGraph 的多场景 CTF / 安全攻防代理
- 主要目录：
  - `app/`：主流程、状态、路由、工具框架、LLM 客户端
  - `tools/`：本地工具封装，含高权限工具
  - `internal_network/`：内网与后渗透能力
  - `remote_executor/`：WebShell / SSH / Impacket / MSF 会话
  - `web/`：Flask Web UI 与 API
  - `tests/`：现有测试
  - `docs/`：设计、评估、计划类文档

---

## 高风险提醒

本仓库不是普通 Web 应用，而是带有本地执行、远程执行、文件生成、凭据处理能力的安全代理。任何 Agent 在修改时都必须默认以下能力属于“高危面”：

- `tools/python_exec_tool.py`
- `tools/file_creator_tool.py`
- `remote_executor/`
- `internal_network/credential_manager.py`
- `web/api.py`

处理这些区域时必须遵守：

1. 不要默认把来自目标站点、日志、RAG、LLM 输出的内容视为可信输入。
2. 不要扩大本地命令执行、文件写入、SSH 信任、密钥落盘的权限边界。
3. 若新增工具、脚本执行能力或管理接口，必须同时说明威胁模型与关闭/限制手段。

---

## 本地开发与验证

### 基础命令

```bash
pip install -r requirements.txt
python app/ctf_agent_graph.py --help
python web/api.py
```

### 测试现状

当前测试基线并不健康，提交前不要盲信 CI。

- `pytest -q` 当前会因 `tests/test_topology_viz.py` 依赖 `networkx` 而在收集阶段失败。
- `pytest -q tests/test_tool_framework.py tests/test_state_types.py` 当前可运行，但仍有工具注册相关失败。
- `.github/workflows/ci.yml` 里的测试步骤目前会吞掉 `pytest` 失败，不能作为“绿灯即安全”的依据。

### 建议的提交前检查

如果你改的是文档：

```bash
git diff --check
```

如果你改的是 Python 代码：

```bash
pytest -q tests/test_tool_framework.py tests/test_state_types.py
python verify_system.py
```

如果你改了 `web/`、`remote_executor/`、`tools/`、`internal_network/`：

- 在 PR 描述中写明风险影响面
- 写明是否涉及本地执行、远程执行、凭据、文件写入、开放接口
- 明确回归验证方式

---

## GitHub 协作规范

### 分支命名

优先使用以下前缀：

- `feature/<topic>`：新功能
- `fix/<topic>`：缺陷修复
- `docs/<topic>`：文档更新
- `refactor/<topic>`：重构
- `test/<topic>`：测试修复或补充
- `chore/<topic>`：基础设施、依赖、脚本

说明：

- 仓库现有 `docs/CONTRIBUTING.md` 使用 `docs/*` 作为文档分支前缀。
- 若任务明确要求 `doc/*`，可以按任务要求执行，但默认规范仍建议 `docs/*`。

### Commit 规范

统一使用 Conventional Commits：

- `feat:`
- `fix:`
- `docs:`
- `refactor:`
- `test:`
- `chore:`

额外要求：

- 一个 commit 只做一类事情，避免“代码修复 + 格式化全仓 + 文档更新”混在一起。
- 做完一个可验证的最小变更单元后，应及时提交，不要长时间堆积在本地工作区。
- 默认要求及时推送到远程分支，避免只有本地副本。
- 如果一次任务修改了大量文件，必须按原子化提交准则拆分：
  - 每个 commit 只表达一个明确目的
  - 代码修复、测试补充、文档更新、重构拆开提交
  - 每个 commit 都应尽量处于可审阅、可回滚、可解释状态
- 不要提交生成物、密钥、会话文件、本地缓存。

### Pull Request 规范

PR 描述至少包含：

1. 变更目的
2. 影响范围
3. 验证方式
4. 风险与回滚方式

如果改动涉及以下区域，必须额外说明：

- `web/api.py`：是否新增暴露接口、认证、配置入口
- `remote_executor/`：是否影响 SSH / WebShell / 会话持久化
- `tools/`：是否引入新的执行器、路径写入点、外部依赖
- `app/tool_framework.py`：是否影响工具注册、选择、兼容接口

### Review 与合并

- 至少 1 个 Reviewer 批准再合并
- 不要在未说明测试现状的情况下声称“CI 已通过”
- 优先 `Squash and merge`
- 合并后删除分支

---

## Agent 工作约束

### 修改前

- 先读 `README.md`
- 再读目标模块的直接依赖文件
- 涉及工具系统时，先确认 `tools/__init__.py` 与 `app/tool_framework.py` 的当前行为

### 修改时

- 优先小改动，避免无关重排
- 不要顺手“修格式”整仓
- 不要把安全工具的“攻击能力”误当成普通字符串处理逻辑
- 不要把凭据、session、日志样本写入可提交路径

### 修改后

- 说明实际执行了哪些验证
- 如果没法跑通测试，要明确写原因
- 如果发现现有测试或 CI 本身有问题，要在 PR 中单独标注，不要略过
- 除非任务明确要求暂存本地，否则应在完成当前阶段后及时 `commit` 并 `push`

---

## 当前已知仓库问题

截至 2026-04-01，至少存在以下需要特别注意的现状：

1. Web 管理面缺少认证与来源限制。
2. 会话信息存在明文持久化风险。
3. SSH 主机指纹校验被关闭。
4. 工具系统存在懒加载与测试预期不一致的问题。
5. 拓扑相关依赖未在 `requirements.txt` 中完整体现。
6. CI 测试步骤会吞掉失败结果。

这些问题意味着：

- 不要把当前默认部署方式当成生产安全基线。
- 不要在未加隔离的主机上直接对不可信目标运行完整代理。

---

## 禁止项

- 禁止提交 `.env`、`config.yaml`、`data/sessions.json`、私钥、密码、外部平台 Token
- 禁止为了“让测试变绿”而删除失败断言或在 CI 中继续吞错
- 禁止在未说明理由的情况下新增 `shell=True`、任意路径写入、关闭 TLS 校验、关闭 SSH 主机校验
- 禁止把高危接口直接暴露到公网而不加认证
