# Intake Checklist

确认输入和评估模式。

## 确认提供的内容

### 必须确认

- [ ] 目标 URL 或 base URL
- [ ] API 类型 (REST/GraphQL/混合)
- [ ] 认证方式 (Bearer Token/JWT/Session/API Key/OAuth)
- [ ] 测试账户 (如有)
- [ ] 授权范围

### 需要明确的

- [ ] 是否允许主动测试
- [ ] 是否有速率限制
- [ ] 测试环境还是生产环境
- [ ] 是否有 IP 白名单

## 评估模式

### 1. 文档驱动审查 (Document-Driven Review)

**条件**: 只有规范、schema、collection 可用

**方法**:
- 分析 OpenAPI/Swagger
- 分析 Postman collection
- 分析 API 文档
- 分析 GraphQL schema

**限制**:
- 无法验证运行时行为
- 无法确认绕过
- 标记为 hypothesis

### 2. 被动目标审查 (Passive Target Review)

**条件**: 存在活动目标，但凭证或主动测试受限

**方法**:
- 观察公开端点行为
- 分析响应结构
- 识别认证边界
- 检查信息泄露

**限制**:
- 无法测试所有边界
- 无法验证授权问题

### 3. 授权主动评估 (Authorized Active Assessment)

**条件**: 用户提供足够授权和上下文

**方法**:
- 测试认证机制
- 验证授权边界
- 测试输入处理
- 验证业务逻辑

**要求**:
- 明确的书面授权
- 测试账户
- 速率限制说明

## 假设声明

如有任何不明确，声明假设：

```
Assumptions:
- [假设 1]
- [假设 2]
```

## 范围限制

```
Scope Limitations:
- [限制 1]
- [限制 2]
```
