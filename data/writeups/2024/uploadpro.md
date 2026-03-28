---
tags: [PHP Opcache利用, 文件上传, 路径穿越, 权限绕过, RCE]
---

# uploadpro

从phpinfo中发现题目使用fpm启动，并且开启了opcache扩展，文件上传功能使用白名单校验。

利用目录穿越读获得index.php源码：

```
<!DOCTYPE html>
<html>
<head>
<title>文件上传</title>
<meta charset="utf-8">
</head>
<body>
<form action="index.php" method="post" enctype="multipart/form-data">
<input type="hidden" name="max_file_size" value="1048576">
<input type="file" name="file">
<input type="submit" name="上传 ">
</form>

</body>
</html>


<?php
if($_SERVER[ 'REQUEST_METHOD']=="GET"){
die(0);
}
header("content-type:text/html;charset=utf-8");
$filename = str_replace("\0","",$_FILES[ 'file'][ 'name']);
$prefix = isset($_GET[ 'prefix'])?str_replace("\0","",$_GET[ 'prefix']):"";
$temp_name = $_FILES[ 'file'][ 'tmp_name'];
$size = $_FILES[ 'file'][ 'size'];
$error = $_FILES[ 'file'][ 'error'];
if ($size > 2*1024*1024){
echo "<script>alert('文件大小超过2M大小');window.history.go(-1);</script>";
exit();
}
$arr = pathinfo($filename);
$ext_suffix = $arr[ 'extension'];
$allow_suffix = array( 'jpg', 'gif', 'jpeg', 'png',"bin","hex","dat","docx","xlsx");
if(!in_array($ext_suffix, $allow_suffix)){ echo "<script>alert('上传的文件类型只能是
jpg,gif,jpeg,png,bin,hex,dat');window.history.go(-1);</script>";
exit();
}
if (move_uploaded_file($temp_name, '/uploads/'.$prefix.$filename)){
echo "<script>alert('文件上传成功 ! Path /uploads/$prefix$filename');</script>"; }else{
echo "<script>alert('文件上传失败 ,错误码： $error');</script>"; }


?>
```

使用docker镜像php:7.4.3-fpm启动环境，安装opcache扩展，创建一个恶意的phpinfo.php并获取其opcache缓存文件phpinfo.php.bin。

新下发一个环境，不访问phpinfo.php，首先访问index.php，再下载index.php.bin，使用插件获取opcache文件的时间戳：https://github.com/GoSecure/php7-opcache-override

将从题目下载得到index.php.bin的时间戳赋值给我们构造的phpinfo.php.bin，然后借助目录穿越将其上传/tmp/opcache/a06090313e406ccd069625aabb3cded7/var/www/html/phpinfo.php.bin，此时再访问phpinfo.php，就成功覆盖，执行恶意代码并获取flag。