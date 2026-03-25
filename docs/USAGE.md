# CTF-Agent 使用指南

## 快速开始

### 1. 启动容器
```bash
cd deploy
docker-compose up -d
```

### 2. 进入容器
```bash
docker exec -it ctf-agent bash
```

### 3. 运行任务
```bash
# 系统自检
python self_check.py

# 运行CTF任务 (命令行模式)
python app/ctf_agent_graph.py --target http://目标地址

# 或使用 Web UI
# 访问 http://localhost:5000
```

---

## 常用命令

### Docker 操作
```bash
# 查看容器状态
docker ps

# 查看日志
docker logs -f ctf-agent

# 进入容器
docker exec -it ctf-agent bash

# 停止容器
docker-compose down

# 重新构建
docker-compose build
```

### 容器内操作
```bash
# 检查工具
which nuclei sqlmap nmap

# 检查Python模块
python -c "from tools import load_all_tools; from tool_framework import ToolRegistry; load_all_tools(ToolRegistry); print(len(ToolRegistry.list_tools()))"

# 测试LLM连接
python -c "from llm_client import llm_client; print(llm_client.chat('Hello')[:50])"
```

---

## 配置文件

### config.yaml 位置
- 本地运行: `deploy/config.yaml`
- 容器内: `/app/config.yaml`

### 修改配置后
```bash
# 本地运行
# 重启web服务即可

# Docker运行
docker-compose restart
```

---

## 目录说明

### 项目目录
```
deploy/
├── app/           # 核心代码
├── tools/         # 安全工具
├── web/           # Web UI
├── config.yaml    # 配置文件
└── docker-compose.yml
```

### 容器内目录
```
/app/
├── ctf_agent_graph.py  # 主程序
├── config.yaml         # 配置
├── tools/              # 工具
├── thirdparty/         # 第三方工具
└── data/               # 数据目录
```

---

## 开发流程

### 修改代码后
```bash
# 重新构建镜像
docker-compose build

# 重启容器
docker-compose up -d
```

### 修改配置后
```bash
# 只需重启
docker-compose restart
```

---

## 故障排查

### 容器启动失败
1. 检查 config.yaml 是否存在
2. 检查 API Key 是否配置
3. 查看日志: `docker logs ctf-agent`

### 工具找不到
```bash
# 检查Go工具
ls /root/go/bin/

# 检查第三方工具
ls /app/thirdparty/
```

### LLM调用失败
1. 检查网络连接
2. 检查 API Key 是否正确
3. 检查 API URL 是否正确