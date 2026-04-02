# Report Template

标准化 API 安全报告模板。

---

## Scope

- **Target**: [目标 URL 或 base URL]
- **Assessment Mode**: [文档驱动/被动/主动]
- **Timeframe**: [评估日期范围]
- **Authorization**: [授权范围说明]

---

## Authorization Assumptions

- [假设已明确授权测试的目标]
- [假设测试环境的限制]
- [其他假设条件]

---

## Asset Summary

### Base URLs

```
- [URL 1]
- [URL 2]
```

### API Type

```
[REST / GraphQL / 混合]
```

### Auth Schemes

```
[认证方式：Bearer Token / JWT / Session / API Key / OAuth]
```

### Discovered Endpoints

| Endpoint | Methods | Auth Required | Risk Level |
|----------|---------|--------------|------------|
| /api/users | GET, POST | Yes | High |
| /api/admin/* | All | Admin | Critical |

### Sensitive Objects

```
- [敏感对象列表]
```

### Trust Boundaries

```
- [信任边界描述]
```

---

## Test Matrix

| Category | Test Item | Priority | Status |
|----------|----------|----------|--------|
| Authentication | 暴力攻击防护 | Critical | Pass |
| Authorization | IDOR | Critical | FAIL |
| Input Handling | SQL Injection | High | - |
| ... | ... | ... | ... |

---

## Findings

### Finding 1: [标题]

**Severity**: [Critical / High / Medium / Low / Informational]

**Confidence**: [Confirmed / High / Medium / Low / Hypothesis]

**Affected Asset**: 
```
[具体 endpoint 或操作]
```

**Description**:
[问题描述]

**Evidence**:
```http
[请求/响应样本]
```

**Reproduction**:
1. [步骤 1]
2. [步骤 2]
3. [步骤 3]

**Impact**:
[现实影响评估]

**Remediation**:
[具体可操作的修复建议]

**Retest Notes**:
[复测需要验证的内容]

---

### Finding 2: ...

---

## Coverage Gaps

| Gap | Impact | Recommendation |
|-----|--------|-----------------|
| [未覆盖的测试区域] | [影响] | [建议] |
| [凭证不足，无法验证...] | [影响] | [建议] |

---

## Overall Risk Summary

| Risk Level | Count | Findings |
|------------|-------|----------|
| Critical | 1 | IDOR in /api/users/{id} |
| High | 2 | ... |
| Medium | 3 | ... |
| Low | 1 | ... |

### Key Risks

- [最重要的 3-5 个风险摘要]

### Recommended Priority

1. [最优先修复项]
2. [次优先]
3. [第三优先]

---

## Appendix

### Tools Used

- [使用的工具列表]

### References

- [参考链接]
