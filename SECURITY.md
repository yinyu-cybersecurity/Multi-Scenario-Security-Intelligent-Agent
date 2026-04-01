# Security Policy

## 🔒 支持的版本

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## 🐛 报告安全漏洞

如果您发现安全漏洞，请**不要**通过公开Issue报告。

### 报告方式

1. **邮件**: 发送详情到项目维护者
2. **私密安全建议**: 使用GitHub Security Advisories

### 报告内容

请包含：

1. **漏洞类型** (e.g. XSS, SQLi, RCE)
2. **影响范围** (哪些功能受影响)
3. **复现步骤** (详细的复现过程)
4. **PoC** (概念验证代码)
5. **影响版本** (受影响的版本号)
6. **修复建议** (如果您有)

### 响应时间

- **确认**: 24小时内
- **初步评估**: 3天内
- **修复计划**: 根据严重性确定
- **发布修复**: 尽快

## 🛡️ 安全最佳实践

### 配置安全

```yaml
# ❌ 不要硬编码敏感信息
LLM_API_KEY: "sk-xxxx"

# ✅ 使用环境变量
LLM_API_KEY: "${LLM_API_KEY}"
```

### 工具调用安全

```python
# ✅ 参数化执行
cmd = ["nmap", target]
subprocess.run(cmd, capture_output=True)

# ❌ 避免shell=True
subprocess.run(f"nmap {target}", shell=True)
```

### 输入验证

所有用户输入在传递给工具前都经过验证：

- Target验证（IP/域名格式）
- URL验证（SSRF防护）
- 端口验证（范围检查）

## 🚨 已知安全问题

| ID | Severity | Description | Fixed in |
|----|----------|-------------|----------|
| CVE-2026-0001 | Critical | 硬编码API密钥 | 2.0.0 |

## 📚 安全资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

感谢您帮助保护CTF-Agent的安全！ 🛡️
