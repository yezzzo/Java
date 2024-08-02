参考教程视频 [Java反序列化RMI专题-没有人比我更懂RMI](https://www.bilibili.com/video/BV1L3411a7ax/?spm_id_from=333.999.0.0&vd_source=686636e30f91f8a12e28751943870859)

参考博客

[RMI反序列化初探](https://cn-sec.com/archives/1591525.html)

[JAVA安全基础（四）-- RMI机制 - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/9261?time__1311=n4%2BxnD0DuAG%3DQD5i%3DD%2FiW4BKGQeeYvNeEN4rQx)

[RMI反序列化漏洞之三顾茅庐-流程分析](https://halfblue.github.io/2021/10/26/RMI%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E4%B9%8B%E4%B8%89%E9%A1%BE%E8%8C%85%E5%BA%90-%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90/)

# RMI应用概述

参考[RMI应用概述](https://docs.oracle.com/javase/tutorial/rmi/overview.html)

RMIClient首先去rmiregistry注册中心查找，RMIServer开启的端口。

之后连接RMIServer。

如果在RMIServer中，找不到，还可以去web中查找加载，这也产生了安全隐患。

![image-20240716095002512](https://s2.loli.net/2024/07/16/lJRXyhrAMtPEodB.png)

流程图

![20210227013102-65c85794-7858-1](https://s2.loli.net/2024/07/16/cM4WBj97DzxqFrR.png)

# DEMO

开两个项目一个RMIClient一个RMIServer

RMIClient

IRemoteObj.java 接口

```java
public interface IRemoteObj extends Remote {
    //sayHello就是客户端要调用的方法，需要抛出RemoteException
    public String sayHello(String keywords) throws RemoteException;
}
```

RMIClient.java 

```java
public class RMIClient {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099); //链接注册中心
        IRemoteObj remoteObj = (IRemoteObj) registry.lookup("remoteObj");  //寻找方法
        remoteObj.sayHello("hello");
    }
}
```

RMIServer

IRemoteObj.java 接口（和client一样的）

```java
public interface IRemoteObj extends Remote {
    //sayHello就是客户端要调用的方法，需要抛出RemoteException
    public String sayHello(String keywords) throws RemoteException;
}
```

RemoteObjImpl.java (服务端需要将接口实现)

```java
public class RemoteObjImpl extends UnicastRemoteObject implements IRemoteObj{

    public RemoteObjImpl() throws RemoteException{
        //UnicastRemoteObject.exportObject(this, 0); //如果不继承UnicastRemoteObject就需要手工导出
    }

    @Override
    public String sayHello(String keywords) {
        String upKeywords = keywords.toUpperCase();
        System.out.println(upKeywords);
        return upKeywords;
    }
}
```

RMIServer.java （RMI服务端创建注册中心，开启端口）

```java
public class RMIServer {
    public static void main(String[] args) throws Exception {
        RemoteObjImpl remoteObj = new RemoteObjImpl();
        Registry registry = LocateRegistry.createRegistry(1099); //创建注册中心
        registry.bind("remoteObj", remoteObj);   //绑定
    }
}
```

写好之后，可以自己测试下。

# 创建远程服务

跟一下`RMIServer.java的RemoteObjImpl remoteObj = new RemoteObjImpl();`

因为RemoteObjImpl()是有父类的，所以RemoteObjImpl()构造方法之前，会先执行其父类的构造函数。

各到父类UnicastRemoteObject的构造函数

```java
//UnicastRemoteObject
protected UnicastRemoteObject(int port) throws RemoteException
{
    this.port = port; //默认为0
    exportObject((Remote) this, port);
}
```

跟进exportObject((Remote) this, port);

```java
public static Remote exportObject(Remote obj, int port)
    throws RemoteException
{
    return exportObject(obj, new UnicastServerRef(port));
}
```

跟进new UnicastServerRef(port)

```java
public UnicastServerRef(int port) {
    super(new LiveRef(port));  //这个LiveRef很重要 //向父类构造参数也传了一个LiveRef
}
```

跟进LiveRef到

```java
public LiveRef(ObjID objID, int port) {
    this(objID, TCPEndpoint.getLocalEndpoint(port), true);
}
```

之后可以看下TCPEndpoint，里面有host，port等，像是个处理网络请求的封装。

**之后LiveRef构造完成，UnicastServerRef(服务端)调用父类UnicastRef(客户端)构造方法传入一个LiveRef。**

最后返回`return exportObject(obj, new UnicastServerRef(port));`

```java
//UnicastRemoteObject
private static Remote exportObject(Remote obj, UnicastServerRef sref)  
    throws RemoteException
{
    // if obj extends UnicastRemoteObject, set its ref.
    if (obj instanceof UnicastRemoteObject) {
        ((UnicastRemoteObject) obj).ref = sref;   //赋值
    }
    return sref.exportObject(obj, null, false);  //调用UnicastServerRef中的exportObject方法
}
```

跟进UnicastServerRef中的exportObject方法

可以看到stub是一个LiveRef（UnicastRef客户端网络请求封装）的动态代理

![image-20240716134516119](https://s2.loli.net/2024/07/16/yEq4lUaoNBmMdK3.png)

接下来走到Target，跟进

```java
Target target =
    new Target(impl, this, stub, ref.getObjID(), permanent);
```

**Target其实就是做了个封装。可以看到服务端和客户端的网络请求LiveRef是一个都是LiveRef@570**

![image-20240716140027871](https://s2.loli.net/2024/07/16/dZzkEgfuQKH2Vcw.png)

接下来的`ref.exportObject(target);`是具体的网络请求。可以跟下视频

TCPTransport的listen方法

![image-20240716143231493](https://s2.loli.net/2024/07/16/dS4voMLDb3wrNkP.png)

他是把接口发布出去了，但是接口号是随机的，现在客户端还不知道服务端的接口。

关于接口的记录是在ObjectTable的

```java
objTable.put(oe, target);
implTable.put(weakImpl, target);
```

完成的。

put之前还涉及到了一个，DGCImpl，这个在后面讲

```java
if (DGCImpl.dgcLog.isLoggable(Log.VERBOSE)) {
    DGCImpl.dgcLog.log(Log.VERBOSE, "add object " + oe);
}
```

# 创建注册中心+绑定

## 创建注册中心

跟下`Registry registry = LocateRegistry.createRegistry(1099); //创建注册中心`

```java
public static Registry createRegistry(int port) throws RemoteException {
    return new RegistryImpl(port);
}
```

之后跟下构造方法RegistryImpl(port);

```java
public RegistryImpl(int port)
    throws RemoteException
{
    if (port == Registry.REGISTRY_PORT && System.getSecurityManager() != null) {
        // grant permission for default port only.
        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                public Void run() throws RemoteException {
                    LiveRef lref = new LiveRef(id, port);
                    setup(new UnicastServerRef(lref));
                    return null;
                }
            }, null, new SocketPermission("localhost:"+port, "listen,accept"));
        } catch (PrivilegedActionException pae) {
            throw (RemoteException)pae.getException();
        }
    } else {
        LiveRef lref = new LiveRef(id, port);   //程序走到这里，新建一个LiveRef,端口是我们写的1099，id是默认值
        setup(new UnicastServerRef(lref));      //之后调用服务端的构造方法，服务端里面又调用客户端的构造方法（和前面一样的）
    }
}
```

接下来看setup

```java
private void setup(UnicastServerRef uref)
    throws RemoteException
{
    /* Server ref must be created and assigned before remote
     * object 'this' can be exported.
     */
    ref = uref;
    uref.exportObject(this, null, true); //这里注意看下和创建远程服务时return sref.exportObject(obj, null, false); 不一样的地方
    //第三个参数对应过去是一个叫永久的属性
}
```

主要区别是第三个参数，

之后运行到

```java
stub = Util.createProxy(implClass, getClientRef(), forceStubUse);
```

跟进Util.createProxy**（主要看）**

```java
public static Remote createProxy(Class<?> implClass,
                                 RemoteRef clientRef,
                                 boolean forceStubUse)
    throws StubNotFoundException
{
    Class<?> remoteClass;

    try {
        remoteClass = getRemoteClass(implClass);
    } catch (ClassNotFoundException ex ) {
        throw new StubNotFoundException(
            "object does not implement a remote interface: " +
            implClass.getName());
    }

    if (forceStubUse ||
        !(ignoreStubClasses || !stubClassExists(remoteClass)))  //这个判断在创建远程服务时是false，但是现在（创建注册中心时）返回true，具体可以看下stubClassExists(remoteClass)
    {
        return createStub(remoteClass, clientRef);       //到这儿就return了，不会执行到下面创建动态代理
    }

    final ClassLoader loader = implClass.getClassLoader();
    final Class<?>[] interfaces = getRemoteInterfaces(implClass);
    final InvocationHandler handler =
        new RemoteObjectInvocationHandler(clientRef);

    /* REMIND: private remote interfaces? */

    try {
        return AccessController.doPrivileged(new PrivilegedAction<Remote>() {   //创建远程服务时会创建动态代理，但是现在（创建注册中心时）走不到这儿
            public Remote run() {
                return (Remote) Proxy.newProxyInstance(loader,
                                                       interfaces,
                                                       handler);
            }});
    } catch (IllegalArgumentException e) {
        throw new StubNotFoundException("unable to create proxy", e);
    }
}
```

stubClassExists

如图，Class.forName可以找到类，不会抛出异常，返回true

![image-20240716163526881](https://s2.loli.net/2024/07/16/NKJ23GShj4CsLtp.png)

创建完stub返回exportObject，进入setSkeleton(impl); **Skeleton，它从 Stub 中接收远程方法调用并传递给真实的目标类。之后会详细讲**

![image-20240716164952666](https://s2.loli.net/2024/07/16/jXOmtg1QFWlYI9V.png)

```java
public void setSkeleton(Remote impl) throws RemoteException {
    if (!withoutSkeletons.containsKey(impl.getClass())) {
        try {
            skel = Util.createSkeleton(impl);   //这个方法是在impl的ref中给skel赋值
        } catch (SkeletonNotFoundException e) {
            /*
             * Ignore exception for skeleton class not found, because a
             * skeleton class is not necessary with the 1.2 stub protocol.
             * Remember that this impl's class does not have a skeleton
             * class so we don't waste time searching for it again.
             */
            withoutSkeletons.put(impl.getClass(), null);
        }
    }
}
```

之后流程与创建远程服务的是一样的

```java
if (stub instanceof RemoteStub) {
    setSkeleton(impl);
}

Target target =
    new Target(impl, this, stub, ref.getObjID(), permanent); //封装Target
ref.exportObject(target);     //开启socket，添加记录
hashToMethod_Map = hashToMethod_Maps.get(implClass);
return stub;
```

看下添加完的记录

能看到UnicastServerRef中skel赋值了，创建远程服务中skel为null

![image-20240716174559518](https://s2.loli.net/2024/07/16/I5s28CqDrMP4cLb.png)

**可以看出来，注册中心的本质也是一个远程服务。**

## 绑定

跟下`registry.bind("remoteObj", remoteObj);`

```java
//RegistryImpl
public void bind(String name, Remote obj)
    throws RemoteException, AlreadyBoundException, AccessException
{
    checkAccess("Registry.bind");
    synchronized (bindings) {   //这个bindings是个hashTable 
        Remote curr = bindings.get(name);  //寻找有没有叫name的key
        if (curr != null)       //如果有则命名冲突抛出异常
            throw new AlreadyBoundException(name);
        bindings.put(name, obj);//没有的话把name，obj put到bindings中
    }
}
```

## 总结

这里引用其他师傅画的流程图，方便理解创建的流程。

![RMI反序列化初探](http://cn-sec.com/wp-content/uploads/2023/03/3-1678156995.png)

# 客户端请求注册中心-客户端（两个攻击点）

跟进LocateRegistry.getRegistry

```java
Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
```

```java
public static Registry getRegistry(String host, int port,
                                   RMIClientSocketFactory csf)   //传入"127.0.0.1", 1099， null
    throws RemoteException
{
    Registry registry = null;

    if (port <= 0)
        port = Registry.REGISTRY_PORT;

    if (host == null || host.length() == 0) {
        // If host is blank (as returned by "file:" URL in 1.0.2 used in
        // java.rmi.Naming), try to convert to real local host name so
        // that the RegistryImpl's checkAccess will not fail.
        try {
            host = java.net.InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            // If that failed, at least try "" (localhost) anyway...
            host = "";
        }
    }
    
    LiveRef liveRef =
        new LiveRef(new ObjID(ObjID.REGISTRY_ID),
                    new TCPEndpoint(host, port, csf, null),
                    false);  //执行到这里 创建LiveRef
    RemoteRef ref =
        (csf == null) ? new UnicastRef(liveRef) : new UnicastRef2(liveRef); //new UnicastRef(liveRef), 将LiveRef赋值给客户端

    return (Registry) Util.createProxy(RegistryImpl.class, ref, false); //这里很熟悉
}
```

**`return (Registry) Util.createProxy(RegistryImpl.class, ref, false);` 这里很熟悉，这个方法是创建Stub用的。**

**这里面走的流程和服务端创建注册中心是一样的，创建的是一个RegistryImpl_Stub对象，不是动态代理。**

接下来跟`IRemoteObj remoteObj = (IRemoteObj) registry.lookup("remoteObj");`

```java
public Remote lookup(String var1) throws AccessException, NotBoundException, RemoteException {
    try {
        RemoteCall var2 = super.ref.newCall(this, operations, 2, 4905912898345647071L);  //用newCall进行通信

        try {
            ObjectOutput var3 = var2.getOutputStream();
            var3.writeObject(var1);   //通过序列化，将要查找的"remoteObj" 写到输出流里面
        } catch (IOException var18) {
            throw new MarshalException("error marshalling arguments", var18);
        }

        super.ref.invoke(var2); //

        Remote var23;
        try {
            ObjectInput var6 = var2.getInputStream();
            var23 = (Remote)var6.readObject(); //获取输入流，将返回值进行反序列化
        } catch (IOException var15) {
            throw new UnmarshalException("error unmarshalling return", var15);
        } catch (ClassNotFoundException var16) {
            throw new UnmarshalException("error unmarshalling return", var16);
        } finally {
            super.ref.done(var2);
        }

        return var23;
    } catch (RuntimeException var19) {
        throw var19;
    } catch (RemoteException var20) {
        throw var20;
    } catch (NotBoundException var21) {
        throw var21;
    } catch (Exception var22) {
        throw new UnexpectedException("undeclared checked exception", var22);
    }
}
```

**这里有两个攻击点**

1. **`var23 = (Remote)var6.readObject(); ` 这里有个反序列化方法，说明客户端和注册中心最终的信息交流是通过序列化的。我们可以构造注册中心攻击客户端。**

2.  **super.ref.invoke(var2); 这个方法**

   跟进invoke方法看看，**注意call.executeCall();这个方法客户端和服务端网络处理都是通过这个方法完成的**

   ```java
   public void invoke(RemoteCall call) throws Exception {
       try {
           clientRefLog.log(Log.VERBOSE, "execute call");
   
           call.executeCall();
   
       } catch (RemoteException e) {
   ```

   之后看StreamRemoteCall 的executeCall方法。有个隐藏的反序列化位置

   ```java
   // read return value
   switch (returnType) {
   case TransportConstants.NormalReturn:
       break;
   
   case TransportConstants.ExceptionalReturn: //如果程序进入这个case
       Object ex;
       try {
           ex = in.readObject();  //则在这儿执行反序列化
       } catch (Exception e) {
           throw new UnmarshalException("Error unmarshaling return", e);
       }
   ```

而且invoke(var2); 这个可利用点，会比1危害大。因为我们可以发现RegistryImpl_Stub的其他方法bind(), list(), rebind()中都有invoke方法。

**最后客户端获取到的是服务端生成的IRemoteObj的代理**

![image-20240717162942890](https://s2.loli.net/2024/07/17/X6DKGnBdPZE4iU3.png)

# 客户端请求服务端-客户端（一个攻击点）

接下来跟

```java
remoteObj.sayHello("hello");
```

因为remoteObj是个动态代理类，（动态代理方法调用都是通过invoke实现的）。所以跟进去是RemoteObjectInvocationHandler的invoke方法。

之后调用了invokeRemoteMethod方法，方法内调用了UnicastRef的invoke方法。

![image-20240717164238983](https://s2.loli.net/2024/07/17/lQXI9VkHiFZdcTw.png)

UnicastRef的invoke方法中，marshalValue中把"hello"序列化。

之后调用了call.executeCall方法**（这一步执行完，服务端就可以看到打印的"HELLO"了）**

![image-20240717164656705](https://s2.loli.net/2024/07/17/menplLOD5dfHyJG.png)

再往下看，因为我们调用的方法是有返回值的，返回HELLO。

如果方法是有返回值的，程序会执行到unmarshalValue(rtype, in);

![image-20240717165241003](https://s2.loli.net/2024/07/17/6UVNjZxmzl5QO43.png)

**这个方法中会调用反序列化方法，这又是一个攻击点。**

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

# 客户端请求注册中心-注册中心（一个攻击点）

这部分调试的是`IRemoteObj remoteObj = (IRemoteObj) registry.lookup("remoteObj");`客户端请求注册中心时，注册中心是如何处理客户端请求的。

由于我们要在服务端开启调试，我们要想想断点需要打在哪（这段可以跟下视频，代码调用太多）。

最后是找到TCPTransport的handleMessages方法，来处理客户端请求的。

```java
//handleMessages
switch (op) {
case TransportConstants.Call:
    // service incoming RMI call
    RemoteCall call = new StreamRemoteCall(conn);
    if (serviceCall(call) == false) //跟进
        return;
    break;
```

最后断点是在 Transport的serviceCall方法中

![image-20240717175237305](https://s2.loli.net/2024/07/17/xIoA9ZJaYNpWUH3.png)

**在前面的创建注册中心时，我们提到了Skeleton，它从 Stub 中接收远程方法调用并传递给真实的目标类。**

**注册中心是通过Skeleton和客户端的Stub进行交互的。下面跟一下代码**

之后`final Dispatcher disp = target.getDispatcher();`从获取到的封装的Target中，拿到分发器dispatch。**在这里我们能看到skel**

![image-20240719105300261](https://s2.loli.net/2024/07/19/YtCeQOJxfuI5hFS.png)

跟进`disp.dispatch(impl, call);`，如果skel不是null，则进入oldDispatch方法。

![image-20240719105724678](https://s2.loli.net/2024/07/19/kmY5ZrAuDgVE4fx.png)

跟进oldDispatch方法，最后会走到`skel.dispatch(obj, call, op, hash);`

这个方法里面很多case，对应着不同的方法。**如果说我们现在传进来是2，对应的就是客户端的lookup('remoteObj')方法。**

**这里存在反序列化，也是一个利用点**

```java
//RegistryImpl_Skel dispatch
case 2:
    try {
        var10 = var2.getInputStream();
        var7 = (String)var10.readObject();  //反序列化，攻击点
    } catch (IOException var89) {
        throw new UnmarshalException("error unmarshalling arguments", var89);
    } catch (ClassNotFoundException var90) {
        throw new UnmarshalException("error unmarshalling arguments", var90);
    } finally {
        var2.releaseInputStream();
    }

    var8 = var6.lookup(var7);  //lookup方法

    try {
        ObjectOutput var9 = var2.getResultStream(true);
        var9.writeObject(var8);
        break;
    } catch (IOException var88) {
        throw new MarshalException("error marshalling return", var88);
    }
```

# 客户端请求服务端-服务端（一个攻击点）

**在上一节，客户端从注册中心lookup到了服务端的动态代理。**

**接下来看服务端是怎么处理客户端的请求的（请求sayHello方法）**

其实接下来收到的分发器是DGCImpl_Skel，这里先不看。往后看第三个请求。第三个请求的Target中stub就是客户端的动态代理了。

![image-20240719113930214](https://s2.loli.net/2024/07/19/VcpNlWuLq3awCMD.png)

之后还是走分发器，但是这里skel为空不走oldDispatch了。

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
            if (num >= 0) {                  //num = -1 (num就是上一节讲的swith(var3) case的var3)，并且skel == null
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

        Method method = hashToMethod_Map.get(op);                         //拿到方法 sayHello
        if (method == null) {
            throw new UnmarshalException("unrecognized method hash: " +
                "method not supported by remote object");
        }

        // if calls are being logged, write out object id and operation
        logCall(obj, method);

        // unmarshal parameters
        Class<?>[] types = method.getParameterTypes();                    //方法的参数类型数组   String
        Object[] params = new Object[types.length];                       // 1

        try {
            unmarshalCustomCallData(in);
            for (int i = 0; i < types.length; i++) {
                params[i] = unmarshalValue(types[i], in);    /////这里比较重要，unmarshalValue在之前客户端请求服务端-客户端时也用到了，是用来反序列化的       拿到的是"hello"
            }
        } catch (java.io.IOException e) {
            throw new UnmarshalException(
                "error unmarshalling arguments", e);
        } catch (ClassNotFoundException e) {
            throw new UnmarshalException(
                "error unmarshalling arguments", e);
        } finally {
            call.releaseInputStream();
        }

        // make upcall on remote object
        Object result;
        try {
            result = method.invoke(obj, params);          //调用sayHello方法 ， 观察到控制台打印 "HELLO"
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }

        // marshal return value
        try {
            ObjectOutput out = call.getResultStream(true);
            Class<?> rtype = method.getReturnType();   //方法返回值类型 这里是 String "HELLO"
            if (rtype != void.class) {
                marshalValue(rtype, result, out);     //如果有返回值的话，需要进行序列化，并发送给客户端
            }
        } catch (IOException ex) {
            throw new MarshalException("error marshalling return", ex);
            /*
             * This throw is problematic because when it is caught below,
             * we attempt to marshal it back to the client, but at this
             * point, a "normal return" has already been indicated,
             * so marshalling an exception will corrupt the stream.
             * This was the case with skeletons as well; there is no
             * immediately obvious solution without a protocol change.
             */
        }
    } catch (Throwable e) {
        logCallException(e);

        ObjectOutput out = call.getResultStream(false);
        if (e instanceof Error) {
            e = new ServerError(
                "Error occurred in server thread", (Error) e);
        } else if (e instanceof RemoteException) {
            e = new ServerException(
                "RemoteException occurred in server thread",
                (Exception) e);
        }
        if (suppressStackTraces) {
            clearStackTraces(e);
        }
        out.writeObject(e);
    } finally {
        call.releaseInputStream(); // in case skeleton doesn't
        call.releaseOutputStream();
    }
}
```

**unmarshalValue方法，里面的反序列化又是一个攻击点**

# 客户端请求服务端-dgc

关于DGC是在put封装的Target时候出现的。

```java
static void putTarget(Target target) throws ExportException {
    ObjectEndpoint oe = target.getObjectEndpoint();
    WeakRef weakImpl = target.getWeakImpl();

    if (DGCImpl.dgcLog.isLoggable(Log.VERBOSE)) {    //在这里调用DGCImpl的静态属性，触发DGCImpl初始化，执行它的静态代码块，放在下面了
        DGCImpl.dgcLog.log(Log.VERBOSE, "add object " + oe);
    }

    synchronized (tableLock) {
        /**
         * Do nothing if impl has already been collected (see 6597112). Check while
         * holding tableLock to ensure that Reaper cannot process weakImpl in between
         * null check and put/increment effects.
         */
        if (target.getImpl() != null) {
            if (objTable.containsKey(oe)) {
                throw new ExportException(
                    "internal error: ObjID already in use");
            } else if (implTable.containsKey(weakImpl)) {
                throw new ExportException("object already exported");
            }

            objTable.put(oe, target);      //put
            implTable.put(weakImpl, target);

            if (!target.isPermanent()) {
                incrementKeepAliveCount();
            }
        }
    }
}
```

DGCImpl静态代码块

```java
static {
    /*
     * "Export" the singleton DGCImpl in a context isolated from
     * the arbitrary current thread context.
     */
    AccessController.doPrivileged(new PrivilegedAction<Void>() {
        public Void run() {
            ClassLoader savedCcl =
                Thread.currentThread().getContextClassLoader();
            try {
                Thread.currentThread().setContextClassLoader(
                    ClassLoader.getSystemClassLoader());

                /*
                 * Put remote collector object in table by hand to prevent
                 * listen on port.  (UnicastServerRef.exportObject would
                 * cause transport to listen.)
                 */
                try {
                    dgc = new DGCImpl();
                    ObjID dgcID = new ObjID(ObjID.DGC_ID);
                    LiveRef ref = new LiveRef(dgcID, 0);
                    UnicastServerRef disp = new UnicastServerRef(ref);
                    Remote stub =
                        Util.createProxy(DGCImpl.class,
                                         new UnicastRef(ref), true);  //这里和注册中心创建skel的时候非常像
                    disp.setSkeleton(dgc);

                    Permissions perms = new Permissions();
                    perms.add(new SocketPermission("*", "accept,resolve"));
                    ProtectionDomain[] pd = { new ProtectionDomain(null, perms) };
                    AccessControlContext acceptAcc = new AccessControlContext(pd);

                    Target target = AccessController.doPrivileged(
                        new PrivilegedAction<Target>() {
                            public Target run() {
                                return new Target(dgc, disp, stub, dgcID, true);
                            }
                        }, acceptAcc);

                    ObjectTable.putTarget(target);    //调用了put，putTarget
                } catch (RemoteException e) {
                    throw new Error(
                        "exception initializing server-side DGC", e);
                }
            } finally {
                Thread.currentThread().setContextClassLoader(savedCcl);
            }
            return null;
        }
    });
}
```

主要看下这两句（结合创建注册中心时候的分析看）

在Util.createProxy，和创建注册中心一样可以找到DGCImpl_Stub，返回的是DGCImpl_Stub，而不是动态代理。

disp.setSkeleton(dgc);是设置skel。

```java
                Remote stub =
                    Util.createProxy(DGCImpl.class,
                                     new UnicastRef(ref), true);  //这里和注册中心创建skel的时候非常像
                disp.setSkeleton(dgc);
```

**DGCImpl_Stub和DGCImpl_Skel中存在readObject和ref.invoke()方法的地方都是存在攻击点的**

