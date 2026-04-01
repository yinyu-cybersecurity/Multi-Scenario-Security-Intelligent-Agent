# Product Roadmap

## Now

### 1. 仓库工厂化骨架

- 建立 `docs/product/`、`docs/architecture/`、`docs/runbooks/`、`specs/`
- 重构 `AGENTS.md` 为总控文档
- 提供 `Makefile` 统一入口
- 补齐 Issue / PR 模板

完成标准：

- 新任务可以通过 docs 与模板启动
- Agent 可以不用猜目录含义就找到目标文档

### 2. 现状显式化

- 明确当前测试、CI、安全边界的真实状态
- 不再用“应该没问题”代替事实记录

完成标准：

- 当前状态能从 `docs/product/current-state.md` 直接读到

---

## Next

### 1. 审计问题系统性修复

- 以 `specs/audit-remediation-program/spec.md` 为总契约推进多 PR 修复
- 覆盖 Web 控制面、凭据与会话处理、高危执行边界、ToolRegistry、测试与 CI
- 每个 workstream 都要求机器可判定验收

### 2. CI 统一到 Makefile

- 让 workflow 使用统一入口，而不是仓库内到处散落命令
- 去掉吞错逻辑，恢复失败即失败

### 3. 测试分层

- 定义 `smoke`、`unit`、`integration`、`security`
- 让测试失败能快速定位到层级，而不是一锅烩

### 4. 规格驱动开发

- 新 feature 和重要 bug 都要求绑定 `specs/*/spec.md`
- PR 必须引用 spec 或 issue

---

## Later

### 1. 权限策略代码化

- 把“谁能做什么”从口头约束升级成仓库策略与平台权限

### 2. 发布流程自动化

- 自动生成 release notes
- 自动执行发布前校验
- 自动沉淀回滚记录

### 3. 文档迁移

- 逐步把旧的零散计划、报告、说明文档归档到分层结构中
