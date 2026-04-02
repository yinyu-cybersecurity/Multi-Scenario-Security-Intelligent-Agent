# Skill-Play 🚀

> OpenClaw 渗透测试技能集合

## 📦 项目结构

```
skill-play/
├── security-testing/                    ⭐ 通用版
│   ├── SKILL.md
│   └── data/                            (85 个文件)
│       ├── web/                         (Web 渗透)
│       └── intranet/                    (内网渗透)
│
└── API-Security-Testing-Optimized/      ⭐ 接口测试版
    ├── core/
    ├── payloads/
    ├── workflows/
    ├── README.md
    └── SKILL.md
```

## 🎯 包含的 Skill

### 1. security-testing (通用版)

**完整的渗透测试知识库**

- 📁 **85 个文件**
- 📚 **覆盖范围**:
  - Web 渗透 (SQL 注入、XSS、RCE、SSRF 等)
  - 内网渗透 (域渗透、横向移动、权限提升等)
- 📖 **用途**: 作为 OpenClaw Skill 使用

**使用方法**:
```bash
# 在 OpenClaw 中调用
skill security-testing sqli
skill security-testing xss
skill security-testing rce
```

---

### 2. API-Security-Testing-Optimized ⭐ 接口测试版

**深度 API 渗透测试引擎**

- 🚀 **7 个核心文件**
- 🔍 **核心能力**:
  - 自动化 API 发现
  - 智能 JS 分析
  - 流量捕获与学习
  - 漏洞自动检测
- 📊 **测试结果**: 发现 76 个 API 端点 (v3.5 的 3 倍)

**使用方法**:
```bash
# 独立运行
cd API-Security-Testing-Optimized
python3 core/deep_api_tester_v55.py http://target.com/ output.md

# 使用 v3.5 基准版
python3 core/deep_api_tester_v35.py http://target.com/ output.md
```

**依赖安装**:
```bash
pip install playwright requests beautifulsoup4
playwright install chromium
```

---

## 📊 版本对比

| 特性 | security-testing | API-Security-Testing-Optimized |
|------|------------------|-------------------------------|
| **类型** | 知识库 | 自动化引擎 |
| **文件数** | 85 | 7 |
| **用途** | 参考文档 | 实际测试 |
| **API 发现** | ❌ | ✅ 76 个端点 |
| **自动化** | ❌ | ✅ 全自动 |
| **推荐** | 📖 学习参考 | 🔧 实际测试 |

---

## 🚀 快速开始

### 作为 OpenClaw Skill 使用

1. **克隆仓库**:
```bash
git clone https://github.com/steveopen1/skill-play.git
```

2. **安装到 OpenClaw**:
```bash
# 复制 security-testing 到 OpenClaw skills 目录
cp -r security-testing ~/.openclaw/skills/

# 或复制 API-Security-Testing-Optimized
cp -r API-Security-Testing-Optimized ~/.openclaw/skills/
```

3. **使用 Skill**:
```bash
# 在 OpenClaw 中调用
skill security-testing sqli
skill API-Security-Testing-Optimized scan
```

### 独立运行 API 测试引擎

```bash
cd API-Security-Testing-Optimized

# 安装依赖
pip install playwright requests beautifulsoup4
playwright install chromium

# 运行测试
python3 core/deep_api_tester_v55.py http://target.com/ report.md
```

---

## 📚 文档

- **[security-testing/SKILL.md](security-testing/SKILL.md)** - 原始版 Skill 文档
- **[API-Security-Testing-Optimized/README.md](API-Security-Testing-Optimized/README.md)** - v5.5 使用文档
- **[API-Security-Testing-Optimized/SKILL.md](API-Security-Testing-Optimized/SKILL.md)** - v5.5 Skill 文档

---

## 🛠️ 功能特性

### security-testing (原始版)

- ✅ **SQL 注入** - MySQL/MSSQL/Oracle/PostgreSQL/MongoDB
- ✅ **XSS** - 反射型/存储型/DOM 型
- ✅ **RCE** - 远程代码执行
- ✅ **SSRF** - 服务端请求伪造
- ✅ **文件包含** - LFI/RFI
- ✅ **XXE** - XML 实体注入
- ✅ **SSTI** - 模板注入
- ✅ **内网渗透** - 域渗透/横向移动/权限提升

### API-Security-Testing-Optimized (v5.5)

- ✅ **智能 API 发现** - 从 JS 文件自动提取 API 端点
- ✅ **无头浏览器爬取** - Playwright 执行 JS 发现动态路由
- ✅ **流量捕获** - 实时拦截 XHR/Fetch 请求
- ✅ **漏洞检测** - SQL 注入/XSS/未授权访问/敏感数据暴露
- ✅ **智能去重** - 自动去重 API 端点
- ✅ **报告生成** - 自动生成 Markdown 测试报告

---

## 📈 测试结果

### API-Security-Testing-Optimized v5.5

**测试目标**: http://xxxxx/

| 指标 | 结果 |
|------|------|
| JS 文件分析 | 2 个 |
| API 端点发现 | **76 个** |
| 敏感信息 | 4 个 token |
| 漏洞数量 | 6 个 |
| 测试时长 | ~2 分钟 |

**发现的 API 示例**:
```
✅ /users/add
✅ /users/edit
✅ /users/importRecord
✅ /projects/add
✅ /projects/edit
✅ /organ/units
✅ /organ/experts
✅ /system/sysUser/page
✅ /smartmine/dictData/list
...
```

---

## ⚠️ 免责声明

**本工具仅供教育和研究目的使用**

- ✅ 仅用于合法授权的安全测试
- ✅ 仅用于自己拥有的系统
- ✅ 仅用于获得书面授权的系统
- ❌ 禁止用于未授权的系统
- ❌ 禁止用于恶意攻击
- ❌ 禁止用于非法活动

**使用本工具即表示您同意**:
1. 仅用于合法目的
2. 获得适当授权
3. 遵守当地法律法规

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

### 添加新 Skill

1. Fork 本仓库
2. 创建新分支 `git checkout -b feature/new-skill`
3. 添加你的 Skill 到对应目录
4. 提交更改 `git commit -m 'feat: add new skill'`
5. 推送到分支 `git push origin feature/new-skill`
6. 创建 Pull Request

---

## 📄 许可证

MIT License

---

## 👤 作者

- **steveopen1**
- **Email**: hyshyshys27777@gmail.com
- **GitHub**: https://github.com/steveopen1

---

## 🙏 致谢

感谢所有贡献者和使用者！

---

**🌟 如果这个项目对你有帮助，请给一个 Star！**
