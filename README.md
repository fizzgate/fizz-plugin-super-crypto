# fizz-plugin-super-crypto
### 一、功能概况
Fizz加解密插件支持GET / POST请求报文做加解密处理。插件配置支持数据类型，密钥类型，算法类型，加密模式，密钥条件进行选择，加解密算法支持对称算法，非对称算法，摘要算法进行处理，
可以对请求request.headers，request.queryParams，reqeust.body，response.headers，response.body数据进行加解密处理，可以指定字段进行加解密，也可以默认全报文进行加解密。

#### 插件使用说明
1. 数据类型
	- requestHeader，支持对Request中的header数据进行加解密
    - request，支持对GET请求中的queryParams请求参数，POST请求中的request.body数据进行加解密
    - responseHeader，支持对Response中的header数据进行加解密
    - response，支持对请求响应中的request.body数据进行加解密

2. 密钥类型
    - 公钥与私钥，非对称算法时选择
    - 密钥，对称算法是选择
3. jsonPath：指定字段做加解密处理
	- json数据做加解密通过jsonPath语法指定字段，例如：$..id 表示所有id节点
	- GET请求对请求参数加解密时，直接录入字段名，多个字段名用英文逗号分隔，例如：id,name 表示对id和name参数值做加解密处理
	
4. 算法类型
    - 对称加解密算法：  AES， DES， ARCFOUR， Blowfish， DESede， RC2。 参考： <https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator>
	- 非对称加解密算法： RSA， RSA / ECB / PKCS1Padding， RSA / ECB / NoPadding， RSA / None / NoPadding。 参考： <https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator>
	- 摘要算法： MD2， MD5， SHA - 1， SHA - 256， SHA - 384， SHA - 512 参考： <https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest>
	
5. 加密模式：分为加密，解密


### 二、注意事项
1. 如果是对body数据做加解密处理，数据格式要求是json格式数据。
2. 加解密后返回的数据为String型数据，数据解析需注意。
3. 摘要算法是不可逆的， 理论上无法通过反向运算取得原数据内容， 因此它通常只能被用来做数据完整性验证。
4. 如果是处理body，jsonPath为空是会对整个报文做加解密，数据解析时要特别注意，如果是处理header，jsonPath为空则不做处理。


I、gateway项目pom文件中引入以下依赖：

```xml
<dependency>
    <groupId>com.fizzgate</groupId>
    <artifactId>fizz-plugin-super-crypto</artifactId>
    <version>${fizz.version}</version>
</dependency>
```

II. 管理后台导入以下SQL

 ```sql
     INSERT INTO `tb_plugin` (`fixed_config`, `eng_name`, `chn_name`, `config`, `order`, `instruction`, `type`, `create_user`, `create_dept`, `create_time`, `update_user`, `update_time`, `status`, `is_deleted`) VALUES 
     ('', 'superCryptoPlugin', '加解密插件', '[{"field":"cryptoType","label":"数据类型","component":"select","dataType":"string","options":[{"label":"requestHeaders","value":"requestHeadersCrypt"},{"label":"request","value":"requestCrypt"},{"label":"responseHeaders","value":"responseHeadersCrypt"},{"label":"response","value":"responseCrypt"}],"desc":"选择加解密的数据类型,分为request 和 response，注：body为json格式数据","placeholder":"请选择","rules":[{"required":true,"message":"数据类型不能为空","trigger":"change"}]},{"field":"secretKey","label":"密钥","component":"textarea","dataType":"string","desc":"密钥,格式是base64字符串","placeholder":"3frPWviKGx6gCD1KDnFcTw==","default":"","options":[],"rules":[]},{"field":"keyType","label":"密钥类型","component":"radio","dataType":"number","default":1,"options":[{"label":"公钥","value":1},{"label":"私钥","value":2},{"label":"密钥","value":3}],"desc":"密钥类型，对称算法为密钥，非对称算法可以选公钥或私钥，摘要算法不影响","rules":[{"required":true,"message":"请选择密钥类型","trigger":"change"}]},{"field":"jsonPath","label":"jsonPath","component":"input","dataType":"string","desc":"1、request.body或response.body可以指定json中节点进行加解密处理，如果此项为空则会对整个报文进行加解密处理。JsonPath语法参考https://goessner.net/articles/JsonPath/index.html,例如：$..id 表示所有id节点;2、如果是GET请求中对请求参数进行加解密处理,可以指定字段名，多个字段用英文逗号分隔，为空这所有参数值做加解密处理","placeholder":"json格式数据按jsonPath语法填写,GET请求参数按参数名填写，多个使用英文逗号分隔","default":"","options":[],"rules":[]},{"field":"algorithm","label":"算法","component":"select","dataType":"string","options":[{"label":"AES","value":"AES"},{"label":"DES","value":"DES"},{"label":"ARCFOUR","value":"ARCFOUR"},{"label":"Blowfish","value":"Blowfish"},{"label":"DESede","value":"DESede"},{"label":"RC2","value":"RC2"},{"label":"RSA","value":"RSA"},{"label":"RSA/ECB/PKCS1Padding","value":"RSA/ECB/PKCS1Padding"},{"label":"RSA/ECB/NoPadding","value":"RSA/ECB/NoPadding"},{"label":"RSA/None/NoPadding","value":"RSA/None/NoPadding"},{"label":"MD2","value":"MD2"},{"label":"MD5","value":"MD5"},{"label":"SHA-1","value":"SHA-1"},{"label":"SHA-256","value":"SHA-256"},{"label":"SHA-384","value":"SHA-384"},{"label":"SHA-512","value":"SHA-512"}],"desc":"共分为三种类型加解密算法类型1、对称加解密算法： AES， DES， ARCFOUR， Blowfish， DESede， RC2。 参考： https: //docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator 2、非对称加解密算法： RSA， RSA / ECB / PKCS1Padding， RSA / ECB / NoPadding， RSA / None / NoPadding。 参考： https: //docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator 3、摘要算法： MD2， MD5， SHA - 1， SHA - 256， SHA - 384， SHA - 512 参考： https: //docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest 注： 摘要算法是不可逆的， 理论上无法通过反向运算取得原数据内容， 因此它通常只能被用来做数据完整性验证","placeholder":"请选择","rules":[{"required":true,"message":"请选择算法","trigger":"change"}]},{"field":"mode","label":"模式","component":"radio","dataType":"number","default":1,"options":[{"label":"加密","value":1},{"label":"解密","value":2}],"desc":"加解密模式","rules":[{"required":true,"message":"请选择加解密模式","trigger":"change"}]}]', 1, '', 2, NULL, NULL, NULL, NULL, NULL, 1, 0);
 ```

更多网关二次开发请参考[网关快速开发](https://www.fizzgate.com/fizz/guide/fast-dev/fast-dev.html) 、[插件开发样例](https://www.fizzgate.com/fizz/guide/plugin/)