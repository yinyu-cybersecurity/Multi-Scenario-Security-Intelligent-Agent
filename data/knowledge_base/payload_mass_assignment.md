# Mass Assignment - 批量赋值

[SEARCH_KEYWORDS]
漏洞类型: Mass Assignment 批量赋值 Object Binding Parameter Binding
攻击类型: Privilege Escalation Role Manipulation Data Tampering
关键词: mass assignment ORM bind parameters object properties attributes
框架: Ruby on Rails Django Laravel Spring Boot ASP.NET
技术: Parameter Injection Role Escalation Admin Flag Injection

[CONTENT]

## 批量赋值概述

批量赋值攻击是一种安全漏洞，当Web应用程序自动将用户提供的输入值分配给程序对象的属性或变量时发生。如果用户能够修改他们不应有权访问的属性（如用户权限或管理员标志），这就会成为问题。

## 漏洞原理

批量赋值漏洞在使用ORM技术的Web应用程序中最常见，属性可以一次性更新而非单独更新。

受影响框架：
- Ruby on Rails
- Django
- Laravel (PHP)
- Spring Boot
- ASP.NET

## 攻击示例

### 基础场景

用户对象属性：`username`, `email`, `password`, `isAdmin`

正常请求：
```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password"
}
```

攻击请求：
```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

如果Web应用程序不检查允许更新的参数，可能会设置`isAdmin`属性。

### 常见攻击目标

| 属性 | 攻击效果 |
|------|----------|
| isAdmin | 提升为管理员 |
| role | 修改用户角色 |
| isVerified | 绕过验证 |
| credits | 修改账户余额 |
| price | 修改商品价格 |
| status | 修改订单状态 |

## 测试方法

1. 识别用户对象的所有属性
2. 尝试添加隐藏属性到请求
3. 观察是否影响用户权限或数据

## 防护措施

### 白名单方法

只允许特定属性被更新：

```python
# Django示例
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']  # 不包括isAdmin
```

### 黑名单方法

排除敏感属性：

```ruby
# Ruby on Rails示例
def user_params
  params.require(:user).permit(:username, :email, :password)
end
```

## 参考文档

原始来源: PayloadsAllTheThings/Mass Assignment/README.md