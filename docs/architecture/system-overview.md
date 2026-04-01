# System Overview

## 总体结构

仓库当前可以按职责分成五层：

1. 入口层
2. 编排层
3. 场景层
4. 执行层
5. 数据与运行时层

---

## 分层图

```text
README / AGENTS / docs / specs
            |
            v
CLI / Web API / scripts
            |
            v
app/ (state, router, tool framework, llm client, orchestration)
            |
            +-----------------------------+
            |                             |
            v                             v
scenario modules                   tools / remote_executor
(internal_network, crypto,         (local commands, remote sessions,
 pwn, reverse, misc,                shells, third-party integrations)
 ai_security, cloud_security)
            |
            v
data/ + logs + sqlite + generated artifacts
```

---

## 当前主流程

### Web / CLI 请求进入

- Web UI 入口在 `web/`
- CLI 主入口在 `app/ctf_agent_graph.py`

### 编排层决策

- `app/` 负责状态、路由、提示词、工具注册、图执行和结果归并

### 场景模块执行

- 每个领域模块负责本场景节点和能力组合

### 工具层与远程执行

- `tools/` 负责本地工具封装
- `remote_executor/` 负责会话、SSH、WebShell、Impacket、MSF 等执行通道

### 数据落盘

- 运行期数据主要进入 `data/`
- 还有日志、任务状态、向量库等运行时内容

---

## 工厂模式下的系统事实来源

机器接手时，不应直接从代码反推一切规则，而应按以下顺序取事实：

1. `docs/product/`：为什么做、现在是什么状态
2. `docs/architecture/`：模块边界、设计约束
3. `docs/runbooks/`：如何操作、如何发布、如何回滚、如何控权
4. `specs/`：这次任务具体要达到什么
5. 代码：实现细节

---

## 当前限制

- 本文描述的是逻辑分层，不代表代码已经完全解耦
- 本轮治理不强制移动现有代码，只建立稳定的文档与协作骨架
