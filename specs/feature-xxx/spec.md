# Feature Spec Template

## Metadata

- Feature: `feature-xxx`
- Status: Draft
- Owner:
- Linked Issue:
- Linked PR:

---

## Problem

<!-- 当前缺口是什么 -->

## Goal

<!-- 这次改动要明确得到什么 -->

## Non-goals

<!-- 这次明确不做什么 -->

## Scope

### In Scope

- 

### Out of Scope

- 

---

## Proposed Changes

1.
2.
3.

---

## Machine-checkable Acceptance Criteria

1. 
2. 
3. 

要求：

- 不写“优化一下”“体验更好”“更智能”这种不可判定描述
- 每条验收都应能通过测试、命令输出或文件变化来判断

---

## Validation Commands

```bash
make lint
make test
make security
```

---

## Documentation Updates

- [ ] `docs/product/`
- [ ] `docs/architecture/`
- [ ] `docs/runbooks/`
- [ ] `AGENTS.md` only if the top-level operating model changes

---

## Rollout / Rollback Notes

### Rollout

<!-- 如何上线或合入 -->

### Rollback

<!-- 如果失败，如何撤销 -->
