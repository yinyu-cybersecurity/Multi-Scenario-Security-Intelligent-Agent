---
name: linux-forensics
description: Use when encountering Linux 应急响应 - 文件排查、进程排查、隐藏进程、日志分析、挖矿木马、系统命令替换
---

# Linux 应急响应

## Info

- **Tags**: linux, forensics, incident-response, malware
- **场景**: 挖矿木马、Webshell、Rootkit、SSH 后门

---

## 1. 文件排查

```bash
# 最近修改的文件
ls -alt /tmp/ | head -n 20
ls -alt /var/tmp/ /dev/shm/ | head -n 20

# 当前目录最近 10 个修改的文件
ls -alt | head -n 10

# 查找 24 小时前修改的 PHP 文件
find ./ -mtime +0 -name "*.php"

# 查看 72 小时内新增的文件
find / -ctime 2 -type f 2>/dev/null | head -50

# 查看文件详细时间
stat /etc/passwd
# Access: 访问时间 | Modify: 内容修改 | Change: 状态修改

# 隐藏文件
ls -ar | grep "^\."

# 特殊权限文件
find / -perm 777 2>/dev/null

# 恶意文件搜索
find /tmp /var/tmp /dev/shm /usr/bin /root -type f \
  \( -name ".*.sh" -o -name ".*.php" -o -name ".*.bin" -o -name ".*.elf" \
  -o -name "*sysupdate" -o -name "*watchdog" -o -name "*kinsing" -o -name "*xmr" \) 2>/dev/null
```

---

## 2. 进程排查

```bash
# 动态查看
top

# 查看网络连接
netstat -antlp | more

# 定位进程
ps aux | grep <PID>
lsof -i:<PORT>

# 暂停进程（防止守护进程恢复）
kill -STOP <PID>
ps aux | grep -T  # 查看已暂停的进程
```

### 隐藏进程检测

```bash
# 对比 /proc 和 ps 的 PID 差异
comm -23 <(ls /proc | grep -E '^[0-9]+$' | sort -n) <(ps -eo pid --no-headers | tr -d ' ' | sort -n)

# 检查 mount 劫持
cat /proc/$$/mountinfo

# 修复
umount /proc/<HIDDEN_PID>
```

### 系统命令替换检测

```bash
# CentOS/Debian
rpm -Vf /usr/bin/*
# S=大小变 | 5=MD5变 | T=时间变

# Ubuntu/Debian
for cmd in ls cat ps grep find netstat ss top id whoami sudo; do
  pkg=$(dpkg -S /usr/bin/$cmd /bin/$cmd 2>/dev/null | head -n1)
  if [ -z "$pkg" ]; then echo "❗ $cmd (not owned by any package)";
  else echo "OK: $cmd ← ${pkg%%:*}"; fi
done

# 检查文件类型
file /usr/bin/ps
readlink -f /usr/bin/ps
strings /usr/bin/ps | head -20
```

---

## 3. 系统信息排查

```bash
# 可登录用户
cat /etc/passwd | grep -E "/bin/bash$"
awk -F: '{if($3==0)print $1}' /etc/passwd  # UID=0

# 历史命令
cat /root/.bash_history
cat /home/*/.bash_history 2>/dev/null

# 计划任务
crontab -l
ls /etc/cron*
atq

# 开机启动
cat /etc/rc.local
ls -alt /etc/init.d/

# 登录记录
lastlog       # 所有用户最后登录
last          # 最近登录
sudo lastb    # 登录失败

# SSH 公钥检查
ls -la /root/.ssh/
ls -la /home/*/.ssh/ 2>/dev/null

# 动态链接库检查
busybox cat /etc/ld.so.preload
busybox ls -l /lib64/*.so 2>/dev/null

# 处置
rm -f /etc/ld.so.preload
rm -f /lib64/malicious.so
```

---

## 4. 日志分析

```bash
# 认证日志
cat /var/log/auth.log        # Ubuntu
cat /var/log/secure          # CentOS

# SSH 爆破分析
grep "Failed password for root" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -20

# 登录成功
grep "Accepted" /var/log/auth.log | awk '{print $9 "@" $11}' | sort -u

# 爆破字典
grep "Failed password for" /var/log/auth.log | awk '{print $9}' | sort -u

# 系统日志
cat /var/log/syslog          # Ubuntu
cat /var/log/messages        # CentOS

# Web 日志
cat /var/log/nginx/access.log
cat /var/log/apache2/access.log
```

### Webshell 日志特征

```
Darkblade: goaction=login
JspSpy:    o=login
PhpSpy:    action=phpinfo
Regeorg:   cmd=connect
通用:      cmd= | eval( | assert(
```

---

## 5. 挖矿木马专项

```bash
# 判断：CPU 占用率居高不下

# 处置流程：计划任务 → 开机启动 → 守护进程 → 异常进程

# 网络隔离
iptables -I INPUT -s <维护IP> -p tcp -j ACCEPT
iptables -A INPUT -p tcp -j DROP
iptables -A OUTPUT -p tcp -j DROP
# 清除
iptables -F

# 暂停进程
kill -STOP <PID>

# 删除文件
rm -fv /tmp/.backdoor
```

---

## CTF 检查清单

- [ ] `top` 查看高 CPU 进程
- [ ] `netstat -antlp` 查看可疑连接
- [ ] `ls -alt /tmp/ /var/tmp/ /dev/shm/` 查看临时目录
- [ ] `crontab -l` + `ls /etc/cron*` 查计划任务
- [ ] `cat /root/.bash_history` 查命令历史
- [ ] `rpm -Vf /usr/bin/*` 查命令替换
- [ ] `comm -23` 对比 /proc 和 ps 查隐藏进程
- [ ] `/etc/ld.so.preload` 查动态链接库劫持
- [ ] SSH 公钥检查 `~/.ssh/authorized_keys`
- [ ] 日志分析 SSH 爆破和登录成功记录
