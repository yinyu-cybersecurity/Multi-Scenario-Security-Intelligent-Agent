# API Key Leaks - API密钥泄露

[SEARCH_KEYWORDS]
漏洞类型: API Key Leaks Token Leaks Secret Leaks 密钥泄露 凭证泄露
攻击类型: Unauthorized Access Data Breach Credential Theft Account Takeover
关键词: API key token secret credential hardcoded public repository
泄露源: GitHub DockerHub Logs Config Files .env AWS credentials
平台: AWS Google Cloud Azure Stripe Telegram Slack

[CONTENT]

## API密钥泄露概述

API密钥和令牌是用于管理权限和访问公共/私有服务的认证形式。泄露这些敏感数据可能导致未授权访问、安全受损和潜在数据泄露。

## 常见泄露原因

### 源代码硬编码

```py
# 硬编码API密钥示例
api_key = "1234567890abcdef"
```

### 公共仓库提交

```ps1
## 扫描GitHub组织
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity

## 扫描GitHub仓库、Issue和PR
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
```

### Docker镜像硬编码

```ps1
# 扫描Docker镜像
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker --image trufflesecurity/secrets
```

### 日志和调试信息

密钥可能在调试过程中被意外记录。

### 配置文件

- `.env` 文件
- `config.json`
- `settings.py`
- `.aws/credentials`

## 验证API密钥

### 密钥模式识别

```yaml
patterns:
  - pattern:
      name: AWS API Gateway
      regex: '[0-9a-z]+.execute-api.[0-9a-z._-]+.amazonaws.com'
      confidence: low
  - pattern:
      name: AWS API Key
      regex: AKIA[0-9A-Z]{16}
      confidence: high
```

### 验证示例

**Telegram Bot API Token**:
```ps1
curl https://api.telegram.org/bot<TOKEN>/getMe
```

## 减少攻击面

`.pre-commit-config.yaml` 配置：

```yml
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.2.0
    hooks:
    -   id: detect-aws-credentials
    -   id: detect-private-key
```

## 工具

- trivy - 漏洞和配置扫描器，搜索API密钥/秘密
- badsecrets - 检测已知或弱密钥
- sign-saboteur - Burp扩展，编辑签名令牌
- secrets-patterns-db - 检测密钥的最大开源数据库
- KeyFinder - 浏览时查找密钥
- keyhacks - 验证泄露API密钥
- truffleHog - 查找凭证
- nuclei-templates - API令牌测试模板

```powershell
nuclei -t token-spray/ -var token=token_list.txt
```

## 参考文档

原始来源: PayloadsAllTheThings/API Key Leaks/README.md