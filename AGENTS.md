# AGENTS.md

## Purpose

本文件是仓库的总控说明。

它只回答三类问题：

1. 这个仓库现在采用什么协作模型
2. Agent 应该先读哪些文档
3. Agent 应该如何写文档、切任务、做提交

所有具体、可执行、可维护的内容，必须放到 `docs/` 或 `specs/` 下的对应位置，而不是继续堆在本文件里。

---

## Operating Model

本仓库正在被设计成“可被机器稳定接手的工厂”，而不是“靠 Agent 猜人类意图”的工作区。

核心含义：

- 规划显式存在于仓库
- 任务边界显式存在于 issue / spec
- 验收标准可由机器判断
- 操作入口统一
- 权限默认最小化

如果一个任务没有对应的 issue、spec、runbook 或 current-state 说明，默认不算准备完成；先补文档，再动代码。

---

## Project Overview

项目本身是一个基于 LangGraph 的多场景安全代理，包含：

- 编排与状态管理：`app/`
- 场景模块：`internal_network/`、`crypto/`、`pwn/`、`reverse/`、`misc/`、`ai_security/`、`cloud_security/`
- 工具与远程执行：`tools/`、`remote_executor/`
- Web 层：`web/`

这类项目天然带有高风险执行面，因此项目相关的安全规则、运行手册和现状快照，统一维护在：

- `docs/product/current-state.md`
- `docs/runbooks/security.md`
- `docs/architecture/module-boundaries.md`

---

## Reading Order

### 开始任何任务前

按下面顺序读取：

1. `README.md`
2. `docs/product/current-state.md`
3. `docs/product/vision.md`
4. `docs/architecture/system-overview.md`
5. `docs/architecture/module-boundaries.md`
6. `docs/runbooks/security.md`
7. 与本次任务对应的 `specs/*/spec.md`

### 如果任务涉及发布或环境

继续读：

1. `docs/runbooks/local-dev.md`
2. `docs/runbooks/release.md`
3. `docs/runbooks/rollback.md`

### 如果任务涉及设计或跨模块接口

继续读：

1. `docs/architecture/tech-decisions/`

---

## Documentation Rules

### 总原则

- 事实写在 docs，不写在聊天里
- 契约写在 specs，不写在模糊描述里
- 操作步骤写在 runbook，不写在口头习惯里

### 文档分工

- `docs/product/`
  - 回答为什么做、现在是什么状态、接下来做什么
- `docs/architecture/`
  - 回答系统如何分层、模块边界是什么、为什么做某个技术决策
- `docs/runbooks/`
  - 回答怎么启动、怎么验证、怎么发布、怎么回滚、怎么控权
- `specs/`
  - 回答这次任务的边界、非目标、验收标准和验证命令

### 文档编写要求

写文档时遵守：

1. 用明确词，不用“优化一下”“尽量”“更好”这种无法判定的词。
2. 验收标准必须机器可判定。
3. 变更影响到行为边界时，必须同步更新相应 docs。
4. 如果本次任务改变了流程、发布、回滚、安全、模块边界，不允许只改代码不改文档。

### specs 编写要求

每个 spec 至少写清楚：

1. Problem
2. Goal
3. Non-goals
4. Scope
5. Proposed Changes
6. Machine-checkable Acceptance Criteria
7. Validation Commands
8. Rollout / Rollback Notes

---

## Execution Rules

### 任务切分

- 单次任务最好只改一个 feature、一个 bug 或一类依赖
- 如果一次改动涉及很多文件，必须按原子提交准则拆分
- 如果需求本身太大，先写 spec，再拆里程碑

### 统一入口

优先使用仓库统一入口，而不是临时拼命令：

- `make help`
- `make install`
- `make install-dev`
- `make test`
- `make security`
- `make run-web`

### 验收

所有任务都应有显式验证命令。

如果仓库当前测试不健康，也要把失败显式记录在：

- `docs/product/current-state.md`
- 对应 spec
- PR 描述

而不是静默跳过。

---

## GitHub Collaboration Rules

### Branches

推荐使用：

- `feature/<topic>`
- `fix/<topic>`
- `docs/<topic>`
- `refactor/<topic>`
- `test/<topic>`
- `chore/<topic>`

如果任务要求使用其他前缀，可以按任务要求执行，但必须在 PR 中说明原因。

### Commits

统一使用 Conventional Commits。

强制要求：

- 做完一个可验证的最小单元后及时提交
- 及时推送到远端分支
- 大任务拆成多个原子提交
- 不把文档、重构、修复、测试补充混成一个无法审阅的大提交

### Pull Requests

每个 PR 都应能回答：

1. 关联的 issue / spec 是什么
2. 改动范围是什么
3. 验收命令是什么
4. 风险是什么
5. 回滚方式是什么
6. 更新了哪些 docs

---

## Permission Model

Agent 默认权限是：

- 建分支
- 改文件
- 跑本地命令
- 跑测试和扫描
- 提交
- 推送分支
- 准备 PR

Agent 默认没有：

- 生产发布权限
- 生产环境直连权限
- 秘钥管理权限
- 绕过审查直接合并受保护分支的权限

具体安全规则见：

- `docs/runbooks/security.md`

---

## What To Update When You Change Things

### 改产品方向或当前事实

更新：

- `docs/product/current-state.md`
- `docs/product/roadmap.md`

### 改模块边界、流程或公共接口

更新：

- `docs/architecture/system-overview.md`
- `docs/architecture/module-boundaries.md`
- 必要时新增 `docs/architecture/tech-decisions/*.md`

### 改启动、测试、发布、回滚或安全操作方式

更新：

- `docs/runbooks/*.md`

### 做 feature / bug / refactor

更新：

- 对应 `specs/*/spec.md`
- 必要时同步更新 `docs/`

---

## Bottom Line

如果某个重要事实、规则、步骤、验收标准只存在于聊天记录里，那这个仓库就还没有进入工厂模式。

Agent 的默认动作应该是：

1. 找文档
2. 补文档
3. 再改代码

而不是先猜。
