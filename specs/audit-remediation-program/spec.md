# Audit Remediation Program Spec

## Metadata

- Feature: `audit-remediation-program`
- Status: Draft
- Owner:
- Linked Issue:
- Linked PR:
- Reference Audit: `docs/PROJECT_AUDIT_2026-04-01.md`

---

## Problem

`docs/PROJECT_AUDIT_2026-04-01.md` 已经明确指出，这个仓库当前仍更接近“研究/竞赛环境中的高权限安全代理”，而不是可以被稳定接手、稳定验证、稳定协作的受控代码库。

当前问题不是单点 bug，而是一组相互耦合的系统性缺口：

1. Web 控制面默认裸露，认证、CORS、监听地址与权限边界过弱。
2. 会话、凭据与 SSH 信任模型不安全。
3. 宿主机执行与文件写入边界过宽。
4. ToolRegistry 公共契约漂移，测试、验证脚本与实现不一致。
5. 测试、依赖、CI 现状不能稳定阻止回归。
6. 这些问题虽然已经被审计文档记录，但还没有转化成正式的改造契约和分阶段执行计划。

如果没有一份正式 spec，后续修复容易重新退化为：

- 凭经验挑几个点先修
- 在聊天记录里讨论优先级
- PR 各自为政
- 不能判断“何时算修完”

---

## Goal

通过一份正式 spec，规划并驱动一轮跨多 PR 的全面重构与修复，使仓库在以下方面达到明确、可验证的基线：

1. Web 控制面具备最小可接受的默认安全边界。
2. 会话与凭据处理不再以明文持久化和默认信任为前提。
3. 高危本地执行能力被显式收口、隔离或加固。
4. 工具注册与调用契约恢复一致，测试与验证脚本同步。
5. 测试、依赖、CI、统一入口形成可机器判断的回归门槛。
6. 所有改造都能在 docs、runbooks、tests 和 CI 中留下长期可维护的结构化痕迹。

---

## Non-goals

这份 spec 当前不负责：

- 重写整个业务架构
- 替换 LangGraph、LLM 客户端或全部工具生态
- 在这一轮内把仓库升级为“生产级攻防平台”
- 处理所有历史文档迁移
- 解决所有功能型缺陷和所有第三方工具兼容性问题

本 spec 关注的是“把仓库从高风险工作区拉回受控工程基线”，而不是做功能扩张。

---

## Scope

### In Scope

- `web/api.py`
- `remote_executor/`
- `internal_network/credential_manager.py`
- `tools/python_exec_tool.py`
- `tools/file_creator_tool.py`
- `tools/__init__.py`
- `app/tool_framework.py`
- `verify_system.py`
- `tests/`
- `.github/workflows/ci.yml`
- `requirements.txt` 及开发依赖入口
- `docs/runbooks/`
- `docs/product/current-state.md`

### Out of Scope

- 场景模块的业务策略优化
- UI 视觉设计
- RAG 质量优化
- 所有第三方工具的功能增强
- 与真实生产环境的集成发布

---

## Workstreams

### WS1: Web Control Plane Hardening

目标：

- 把 Web API 从“默认可裸露控制面”收紧到“默认本地、默认受控、默认拒绝未授权请求”的状态。

计划改动：

1. 默认监听地址改为 `127.0.0.1` 或显式配置项。
2. 为 `/api/*` 增加统一认证 / 授权入口。
3. 把 `CORS(app)` 改成显式 allowlist 配置。
4. 对高风险接口做权限分级：
   - 启动任务
   - 读任务结果
   - 读会话
   - 改系统配置
5. 将配置读取接口中的敏感字段最小化暴露。
6. 对认证失败、权限失败和配置修改动作增加审计日志。

### WS2: Session, Secret and SSH Trust Hardening

目标：

- 移除明文敏感信息默认落盘行为，修复 SSH 默认信任模型与私钥验证分支错误。

计划改动：

1. `data/sessions.json` 不再默认持久化 `password` / `private_key`。
2. 如确有必要持久化敏感信息，必须引入显式配置开关与安全存储抽象。
3. SSH 默认改为严格主机指纹校验。
4. 修复 `internal_network/credential_manager.py` 中内存私钥使用错误 API 的问题。
5. 补充 SSH 密码、文件私钥、内存私钥三类验证测试。

### WS3: Execution Boundary Hardening

目标：

- 让高危本地执行与文件写入能力从“默认开放”转为“显式开启、有限边界、可验证收口”。

计划改动：

1. 重新评估 `python-exec` 是否属于默认加载工具。
2. 去掉 `tools/python_exec_tool.py` 中 `shell=True`。
3. 为命令执行引入参数化调用或受限执行策略。
4. 为 `file-creator` 增加文件名净化、路径归一化与输出目录边界检查。
5. 对高危工具增加运行模式说明和显式警告。
6. 在 docs / runbook 中明确哪些模式下允许启用这些能力。

### WS4: Tool Registry Contract Repair

目标：

- 恢复 ToolRegistry 的单一公共契约，让实现、测试、验证脚本一致。

计划改动：

1. 消除 `ToolRegistry` 中同名方法重复定义。
2. 明确“导入即注册”与“显式加载”中的唯一约定。
3. 更新 `verify_system.py` 以匹配真实加载策略。
4. 更新测试以匹配正式契约，而不是历史假设。
5. 明确 `get_tool_names()`、`get_all_tools()`、`get_tool_detail()` 的返回类型和用途。

### WS5: Test, Dependency and CI Normalization

目标：

- 让回归验证重新可信，让 CI 失败真正代表失败。

计划改动：

1. 补齐拓扑测试依赖。
2. 区分运行时依赖与开发 / 测试依赖。
3. 让 workflow 尽量通过 `Makefile` 或统一入口执行。
4. 删除 CI 中吞错逻辑。
5. 定义最小 smoke / fast regression 集。
6. 为高风险路径补充测试：
   - API 认证与拒绝未授权访问
   - session 持久化不写入秘密
   - SSH 严格校验与私钥分支
   - `python-exec` 不再 `shell=True`
   - `file-creator` 拒绝路径穿越
   - ToolRegistry 契约一致

### WS6: Runbook and State Synchronization

目标：

- 把修复后的行为边界沉淀到 docs，让后续机器接手不需要重新做一次审计。

计划改动：

1. 更新 `docs/product/current-state.md`
2. 更新 `docs/runbooks/security.md`
3. 更新 `docs/runbooks/local-dev.md`
4. 更新必要的 architecture / tech decisions 文档
5. 把每个 workstream 的结果映射到 docs，而不是只留在 PR 中

---

## Delivery Strategy

建议按多 PR 方式推进，而不是一次性大改：

1. PR-1: Web 控制面加固
2. PR-2: 会话 / SSH / 凭据处理加固
3. PR-3: 高危执行边界加固
4. PR-4: ToolRegistry 契约修复
5. PR-5: 测试 / CI / 依赖归一化
6. PR-6: 文档与 runbook 收尾

每个 PR 都必须：

- 引用本 spec
- 只覆盖 1 个 workstream 或其独立子集
- 给出明确验证命令

---

## Machine-checkable Acceptance Criteria

本 spec 关闭前，至少要满足以下条件：

1. 默认配置下，未认证请求访问高风险 Web API 返回 `401` 或 `403`，且服务默认不监听公网地址。
2. `data/sessions.json` 中不再持久化明文 `password` 与 `private_key` 字段。
3. `remote_executor/session_manager.py` 与 `internal_network/credential_manager.py` 默认不再使用 `paramiko.AutoAddPolicy()`。
4. `tools/python_exec_tool.py` 中不再出现 `shell=True`。
5. `tools/file_creator_tool.py` 对路径穿越输入存在显式拒绝逻辑，并有测试覆盖。
6. `app/tool_framework.py` 中 `ToolRegistry.get_tool_names()` 只保留一个正式定义，且返回类型在测试与调用方中一致。
7. `verify_system.py` 不再依赖“`import tools` 即自动注册”这个历史假设。
8. `.github/workflows/ci.yml` 中不再使用 `pip install -r requirements.txt || true` 和 `pytest ... || echo ...` 这类吞错写法。
9. `pytest -q` 能在完整开发依赖安装后成功执行完毕，或失败点被显式标记为 `xfail` / `skip` 并写入当前状态文档。
10. `make test-fast`、`make security`、`make help` 均可正常执行。
11. `docs/product/current-state.md` 与 `docs/runbooks/security.md` 已反映修复后的行为边界。

---

## Validation Commands

本 spec 的各阶段至少应使用以下命令验证：

```bash
make help
make lint
make test-fast
make test
make security
python verify_system.py
```

对于 Web 控制面，还应增加行为验证，例如：

```bash
curl -i http://127.0.0.1:54565/fisher_ctf_agent/api/task/start
```

对于代码边界，还应增加静态验证，例如：

```bash
rg -n "shell=True|AutoAddPolicy|password|private_key" tools remote_executor internal_network
```

注意：

- 上述 `rg` 只是辅助手段，不代替测试
- 验证结果必须写入 PR 描述，不允许只说“已自测”

---

## Documentation Updates

- [x] `docs/product/`
- [x] `docs/architecture/`
- [x] `docs/runbooks/`
- [ ] `AGENTS.md` only if the top-level operating model changes

本次 spec 落地后，后续每个 workstream 完成时都必须继续更新：

- `docs/product/current-state.md`
- `docs/runbooks/security.md`
- 必要时的 `docs/architecture/tech-decisions/*.md`

---

## Risks

### R1: 修复一处，打断另一处

例如：

- 收紧 Web API 后，现有前端或脚本失效
- 收紧 ToolRegistry 后，旧测试和节点调用失效

缓解：

- 采用多 PR 波次
- 每个波次都补对应测试与 runbook

### R2: 为了“让 CI 绿”而降低标准

缓解：

- 不允许继续吞错
- 不允许把真实失败隐藏成“暂时忽略”

### R3: 安全边界与研究能力冲突

缓解：

- 通过显式模式开关区分“研究模式”和“受控模式”
- 默认值必须偏安全

---

## Rollout / Rollback Notes

### Rollout

按 workstream 分阶段合入。

每一阶段合入前必须满足：

1. 关联 PR 已完成
2. 对应测试已新增或修正
3. 对应 docs 已更新
4. 已给出回滚方式

### Rollback

如果某个 workstream 引入明显回归，优先回滚该 workstream 对应 PR，而不是连带撤销全部治理改造。

回滚后必须：

1. 更新 `docs/product/current-state.md`
2. 记录失败原因
3. 重开 issue 或补充本 spec 的风险段
