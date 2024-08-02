参考视频：[fasfjson反序列化漏洞1-流程分析](https://www.bilibili.com/video/BV1bD4y117Qh/?spm_id_from=333.999.0.0&vd_source=686636e30f91f8a12e28751943870859)

# 分析版本

fastjson1.2.24

JDK 8u65

# 分析过程

新建Person类

```java
public class Person {

    private String name;
    private int age;

    public Person() {
        System.out.println("constructor_0");
    }

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
        System.out.println("constructor_2");
    }

    public String getName() {
        System.out.println("getName");
        return name;
    }

    public void setName(String name) {
        this.name = name;
        System.out.println("setName");
    }

    public int getAge() {
        System.out.println("getAge");
        return age;
    }

    public void setAge(int age) {
        this.age = age;
        System.out.println("setAge");
    }
}
```

新建JSONTest

```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

public class JSONTest {
    public static void main(String[] args) throws Exception {
        String s = "{\"@type\":\"Person\",\"age\":18,\"name\":\"tttt\"}";

        JSONObject jsonObject = JSON.parseObject(s);
        System.out.println(jsonObject);
    }
}
```

![image-20240715102848791](https://s2.loli.net/2024/07/15/PBIeQL6Mzf2Ubdw.png)

发现parseObject(s)过程还调用了get方法。详细的过程可以跟一下上面视频。

分析下fastjson的`JSON.parseObject(s);`逻辑

主要逻辑在DefaultJSONParser的parse方法

```java
public static Object parse(String text, int features) {
    if (text == null) {
        return null;
    }

    DefaultJSONParser parser = new DefaultJSONParser(text, ParserConfig.getGlobalInstance(), features);
    Object value = parser.parse();    //主要的逻辑在这儿

    parser.handleResovleTask(value);

    parser.close();

    return value;
}
```

parse()先进行字符串的匹配

```java
case LBRACE: //匹配到左大括号
    JSONObject object = new JSONObject(lexer.isEnabled(Feature.OrderedField));
    return parseObject(object, fieldName);
```

之后进入parseObject

key是@type，进入此循环，**fastjson会尝试将字符串反序列化为输入的@type类**。可以看到进入循环之后会调用loadCLass方法，加载类

![image-20240715142244242](https://s2.loli.net/2024/07/15/SKxLRuEswVhPTfC.png)

TypeUtils.loadClass对输入进行了预处理，不处理的话loadClass默认是不能加载数组类的

![image-20240715143333345](https://s2.loli.net/2024/07/15/nHJ6wCeVNkO4mS8.png)

加载完类之后，继续往下跟。到下面的位置会进行反序列化，跟进去

![image-20240715143853109](https://s2.loli.net/2024/07/15/mtzZM5iOIsCvhr9.png)

```java
public ObjectDeserializer getDeserializer(Type type) {
    ObjectDeserializer derializer = this.derializers.get(type);  //首先查看有没有符合条件的默认的反序列化器，我们自己写的类，肯定是返回null
    if (derializer != null) {
        return derializer;
    }

    if (type instanceof Class<?>) {
        return getDeserializer((Class<?>) type, type);   //之后进入这个方法
    }

    if (type instanceof ParameterizedType) {
        Type rawType = ((ParameterizedType) type).getRawType();
        if (rawType instanceof Class<?>) {
            return getDeserializer((Class<?>) rawType, type);
        } else {
            return getDeserializer(rawType);
        }
    }

    return JavaObjectDeserializer.instance;
}
```

getDeserializer((Class<?>) type, type);方法中，找不到符合条件的反序列化器，则把传入的默认当作JavaBean。

![image-20240715145213169](https://s2.loli.net/2024/07/15/5rP2GcusRmD14tU.png)

在createJavaBeanDeserializer中又调用到了`JavaBeanInfo beanInfo = JavaBeanInfo.build(clazz, type, propertyNamingStrategy);`

通过这个build方法去获取Person的信息，从而创建Person的反序列化器。

这里不详细写了

下面三个循环，第一个寻找public的set方法，第二个寻找public的属性，第三个寻找public的get方法(如果有了对应的set方法，那么这里不在创建get方法)

![image-20240715151747655](https://s2.loli.net/2024/07/15/5p2gbLVWXNahkoD.png)

fastjson还有一个设定是，如果找到了某个属性的set方法，那么get方法就不再add。这个操作是在最后一个循环的下面这里实现的。

![image-20240715164947894](https://s2.loli.net/2024/07/15/nce3t9wiAb2Nh6Q.png)

**这里要说一下根据上面分析，如果针对某个属性只有getter方法，则会创建getter方法，但是fastjson对getter方法的返回值做了判断，需要满足下面条件**

![image-20240731102641050](https://s2.loli.net/2024/07/31/Vh7W1mCGRcv8Qta.png)

之后我们就拿到了需要的反序列化器（这有个关于debug的问题，大家看视频吧，这儿就不写了，更新了Person类）

```java
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

import java.util.Map;

public class Person {
    private String name;
    private int age;
    private Map map;

    public Person() {
        System.out.println("constructor_0");
    }

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
        System.out.println("constructor_2");
    }

    public String getName() {
        System.out.println("getName");
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
        System.out.println("setName");
    }

    public int getAge() {
        System.out.println("getAge");
        return this.age;
    }

    public void setAge(int age) {
        this.age = age;
        System.out.println("setAge");
    }

    public Map getMap() {
        System.out.println("getMap");
        return this.map;
    }
}
```

j接下来执行

![image-20240802113150382](C:\Users\DELL\AppData\Roaming\Typora\typora-user-images\image-20240802113150382.png)

下面可以跟一下反序列化器JavaBeanDeserializer中，是如何调用构造函数，set和get方法的。

在反序列化器JavaBeanDeserializer.deserialze中，只会调用setAge和setName。不会调用getAge和getName方法（上面讲了原因）和getMap（这是因为在JavaBeanDeserializer.deserialze中做了判断）

```java
} else if (fieldClass == float[][].class) {   //上面还有很多类型的判断，但是没有Map类，所以这里为假
    fieldValue = lexer.scanFieldFloatArray2(name_chars);

    if (lexer.matchStat > 0) {
        matchField = true;
        valueParsed = true;
    } else if (lexer.matchStat == JSONLexer.NOT_MATCH_NAME) {
        continue;
    }
} else if (lexer.matchField(name_chars)) {  //检查map是否在JSON中
    matchField = true;
} else {
    continue;
}
```

我们想要输出getMap改一下JSON就行了。`String s = "{\"@type\":\"Person\",\"age\":18,\"name\":\"tttt\",\"map\":{}}";`这样就能输出getMap了。

剩下的getAge和getName是在JSON.toJSON(obj);中完成输出的。

```java
///JSON
public static JSONObject parseObject(String text) {
    Object obj = parse(text);
    if (obj instanceof JSONObject) {
        return (JSONObject) obj;
    }

    return (JSONObject) JSON.toJSON(obj);
}
```

```java
///JSON
if (serializer instanceof JavaBeanSerializer) {
    JavaBeanSerializer javaBeanSerializer = (JavaBeanSerializer) serializer;
    
    JSONObject json = new JSONObject();
    try {
        Map<String, Object> values = javaBeanSerializer.getFieldValuesMap(javaObject);
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            json.put(entry.getKey(), toJSON(entry.getValue()));
        }
    } catch (Exception e) {
        throw new JSONException("toJSON error", e);
    }
    return json;
}
```

```java
public Map<String, Object> getFieldValuesMap(Object object) throws Exception {
    Map<String, Object> map = new LinkedHashMap<String, Object>(sortedGetters.length);
    
    for (FieldSerializer getter : sortedGetters) {
        map.put(getter.fieldInfo.name, getter.getPropertyValue(object));
    }
    
    return map;
}
```

# 利用

下面弹个计算器试试

一、**注意类里面都没有定义map这个属性，但是因为fastjson是按set和get等方法寻找属性的，所以并不影响。**

**要注意setMap中参数必须为1，否则fastjson会报错**

```java
public class Test {
    public void setMap(String map) throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
```

```java
public class JSONTest {
    public static void main(String[] args) throws Exception {
        String s = "{\"@type\":\"Test\",\"map\":\"aaaa\"}";
        JSONObject jsonObject = JSON.parseObject(s);
        System.out.println(jsonObject);
    }
}
```

二、**get方法注意不能有参数**

```java
public class Test {
        public Map getMap() throws IOException { //如果返回类型改为int的话，需要在JSON语句中加入map的赋值，否则不会执行get方法。这样做程序可以在toJSON中执行get方法
            Runtime.getRuntime().exec("calc");
            return new HashMap();
        }
}
```

```java
public class JSONTest {
    public static void main(String[] args) throws Exception {
        String s = "{\"@type\":\"Test\"}";
        JSONObject jsonObject = JSON.parseObject(s);
        System.out.println(jsonObject);
    }
}
```

如果getMap返回类型是Map，而且JSON中还给map赋值了。那么会运行两次getMap（我的Test类里面没有setMap方法）

第一次是在形成反序列化器时

第二次是在toJSON中。