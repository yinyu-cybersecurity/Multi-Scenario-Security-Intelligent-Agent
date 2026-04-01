# Local Development Runbook

## 目的

给本地开发、调试、测试提供统一入口，避免每次靠记忆拼命令。

---

## 前提

- Python 3.10+
- 可选：Docker
- 仓库根目录执行

---

## 首次准备

```bash
cp config.yaml.example config.yaml
make install-dev
```

根据需要补充：

- `config.yaml`
- `.env`

---

## 常用命令

### 查看统一入口

```bash
make help
```

### 启动 Web 服务

```bash
make run-web
```

### 查看 CLI 入口

```bash
make run-cli
```

### 验证仓库基础状态

```bash
make verify
```

### 跑测试

```bash
make test
```

### 跑安全扫描

```bash
make security
```

---

## 已知限制

当前仓库仍有历史问题，见：

- `docs/product/current-state.md`
- `docs/PROJECT_AUDIT_2026-04-01.md`

如果某条命令失败，不要把失败隐藏掉；要把失败记录到对应 spec、issue 或 current-state 中。
