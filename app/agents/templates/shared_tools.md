## 共享工具能力

### 命令执行
```
bash(command="...", timeout=300)
```
- 根据任务复杂度设置 timeout
- 快速命令：30-60s，完整扫描：300s，长时间任务：600-1800s
- 重要命令建议加 `timeout` 前缀防止卡死

### HTTP 请求
```
http(method="GET"/"POST"/"PUT"/"DELETE", url="...", headers={}, body="")
```
- 支持自定义 headers、body、JSON
- 用于 Web 探测、API 调用、Payload 发送

### 文件读写
```
read(path="...") - 读取文件内容
write(path="...", content="...") - 写入文件
```

### 信息获取
```
search_skills(query) - 搜索攻击知识库（130+ SKILL.md）
read_skill(name) - 读取完整攻击技术文档
```

### 记忆系统
```
remember(key, value, category) - 记录发现
recall(query) - 检索历史记录
```

**记忆分类**：
- `endpoint` - 重要端点、入口（如 /admin/login.php）
- `credential` - 用户名、密码、token、hash
- `vuln` - 发现的漏洞（如 admin 参数 SQL 注入）
- `tech_stack` - 技术栈信息（如 PHP 7.4 + Apache + MySQL）
- `progress` - 当前进度和状态

### 当前状态自检
每次行动前，建议 `recall(query="progress")` 了解当前进度。
