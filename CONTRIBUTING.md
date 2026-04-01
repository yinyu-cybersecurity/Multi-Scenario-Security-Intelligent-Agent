# Contributing to CTF-Agent

感谢您有兴趣为CTF-Agent做出贡献！

## 🚀 快速开始

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/CTF-Agent.git
cd CTF-Agent
```

### 2. 环境设置

```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 复制配置文件
cp config.yaml.example config.yaml
# 编辑config.yaml填入API密钥
```

### 3. 运行测试

```bash
pytest tests/
```

## 📝 代码规范

### Python代码

- 遵循PEP 8规范
- 使用类型注解
- 添加文档字符串

```python
def example_function(param: str) -> Dict[str, Any]:
    """示例函数
    
    Args:
        param: 参数说明
        
    Returns:
        返回值说明
    """
    pass
```

### 提交信息

使用约定式提交：

```
feat: 添加新功能
fix: 修复bug
docs: 文档更新
style: 代码格式
refactor: 重构
test: 测试相关
chore: 构建/工具
```

## 🛡️ 安全考虑

### 敏感信息

- **禁止**硬编码API密钥、密码等
- 使用环境变量或config.yaml（已在.gitignore中）
- 工具调用时验证参数，防止命令注入

### 工具开发

```python
# ✅ 正确：参数化执行
cmd = ["nmap", "-p", ports, target]
result = await run_command(cmd)

# ❌ 错误：字符串拼接（命令注入风险）
cmd = f"nmap -p {ports} {target}"
os.system(cmd)
```

## 🧪 测试

### 单元测试

```bash
pytest tests/unit/test_specific_module.py -v
```

### 集成测试

```bash
pytest tests/integration/ -v
```

## 📚 文档

- 更新相关README部分
- 添加函数/类文档字符串
- 更新CHANGELOG.md

## 🔧 添加新工具

1. 在`app/tools_v2/tools/simple_tools.py`添加Schema和Handler
2. 在`TOOL_SCHEMAS`字典注册
3. 在`HANDLERS`字典注册
4. 在Dockerfile添加工具安装
5. 添加测试用例

## 📋 Pull Request流程

1. 创建feature分支
```bash
git checkout -b feature/your-feature
```

2. 提交更改
```bash
git add .
git commit -m "feat: your feature description"
```

3. 推送到Fork
```bash
git push origin feature/your-feature
```

4. 创建Pull Request

## 💬 交流

- 提Issue反馈bug或建议
- 参与Issue讨论
- 提交PR贡献代码

## 📄 许可证

贡献的代码将采用MIT许可证。

---

再次感谢您的贡献！ 🎉
