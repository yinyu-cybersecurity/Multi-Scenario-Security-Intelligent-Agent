# SharePoint攻击

## 1. SharePoint枚举

```powershell
Get-SPWeb
Get-SPList
Get-SPUser
```

## 2. 文件上传

```
/_layouts/15/upload.aspx
```

## 3. 读取敏感文件

```
/sites/dev/SiteAssets/test.txt
/_api/web/GetFileByServerRelativeUrl
```

## 4. 权限提升

```
添加管理员账户
修改权限
```

## 5. SSRF

```
/_api/web/urls
```

## 6. SSTI

```
模板注入
```
