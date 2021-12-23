package we.plugin.crypto;

import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONPath;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricAlgorithm;
import cn.hutool.crypto.asymmetric.AsymmetricCrypto;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.digest.DigestAlgorithm;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import we.plugin.crypto.bean.ParamsEnum;

/**
 *  
 * @author  lml.li
 * @date  2021-9-26 11:41:52
 */
public class CryptoTest {

	/**   
	 * 算法参考：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
	 *  Aes对称加解密，可以指定算法algorithm，密钥长度keySize，指定密钥字符串(base64)
	 */
	@Test
	public void aesCrypto() {
		// 指定base64密钥字符串
		String keyStr = "WXxCSFmbg5lR5zkNpWCq0Q==";

		// 密钥
		byte[] secretKeyByte = SecureUtil.decode(keyStr);

		System.out.println("AES密钥(byte)===" + secretKeyByte);
		System.out.println("AES密钥(String)===" + Base64.encode(secretKeyByte));

		// 待加密字符串
		String dataStr = "{\"code\":\"0\",\"msg\":\"成功\",\"data\":{\"innId\":\"128\",\"chainCode\":\"128\",\"businessType\":\"0\",\"officeCenterType\":\"23\",\"supportPaymentMode\":null,\"forensicCode\":null,\"status\":\"1\",\"innType\":\"0\",\"starType\":\"-1\",\"recommandStarType\":\"0\",\"medalType\":\"5\",\"startFloor\":\"11,13,18-20\",\"endFloor\":\"20\",\"totalRoom\":\"46\",\"brandCode\":\"1\",\"innPhone\":\"123456789012345678901234567890\",\"innEmail\":\"123456@12.cn\",\"innFax\":\"123456\",\"supportPayOnline\":null,\"bookFlag\":\"1\",\"supportForeignGuest\":\"1\",\"valueAddedInvoice\":\"0\",\"chooseRoomSwitch\":\"1\",\"smartHotel\":\"1\",\"openDate\":\"2008-02-29\",\"closeDate\":null,\"ifsync\":\"1\",\"saleDepartId\":\"128\",\"mainPerson\":\"\",\"chineseInfoFull\":\"0\",\"englishInfoFull\":\"0\",\"auditStatus\":\"1\",\"mainPhone\":\"18521738707\",\"valid\":\"1\",\"createDateTime\":\"2018-05-18 10:15:37.0\",\"bookingInvoice\":\"1\",\"invoiceType\":\"2\",\"homeLink\":null,\"crsCode\":\"\",\"pmsCode\":null,\"roomSwitchFlag\":\"1\",\"smoking\":\"1\",\"pullRoomFlag\":\"1\",\"mainEmail\":\"\",\"decorationDate\":\"2019-08-01\",\"elevatorNum\":\"0\",\"meetingRoomNum\":\"0\",\"meetingRoomAccommodates\":\"0\",\"nonSmokingRoomsNum\":\"0\",\"maxCheckIn\":null,\"settlementCurrency\":\"CNY\",\"panoramaImage\":null,\"zipCode\":\"123456\",\"checkInTime\":\"14:00\",\"checkOutTime\":\"12:00\",\"timeZone\":\"GMT+8\",\"pets\":\"0\",\"allowMinors\":\"0\",\"innLevel\":\"0\",\"morningRoom\":\"1\",\"sourceType\":\"7days\",\"countryCode\":\"AR01438\",\"provinceCode\":\"AR04072\",\"cityCode\":\"AR03026\",\"secondCityCode\":\"AR03026\",\"districtCode\":\"AR02145\",\"pmsSourceType\":\"7days\",\"isSupportGuideDogPolicy\":\"1\",\"groupCode\":\"53\",\"diamondRating\":\"5\",\"videoUrl\":\"http://beyond.3dnest.cn/play/?m=zq_hpxed_4&from=singlemessage&isappinstalled=0\",\"vrVideoUrl\":null,\"innName\":{\"0\":\"7天酒店·长沙定王台省人民医院店\"},\"innShortName\":{\"0\":\"7tjd·zsdwtsrmyyd\"},\"innNamePinYin\":{\"0\":\"7tianjiudian·zhangshadingwangtaishengrenminyiyuandian\"},\"salutatory\":{\"0\":\"welcome to hunan\"},\"guide\":{\"0\":\"353543\"},\"countryName\":{\"0\":\"中国\"},\"provinceName\":{\"0\":\"湖南\"},\"cityName\":{\"0\":\"长沙\"},\"secondCityName\":{\"0\":\"长沙\"},\"districtName\":{\"0\":\"芙蓉区\"},\"brandName\":{\"0\":\"7天酒店\"},\"groupName\":{\"0\":\"铂涛集团\"},\"description\":{\"0\":\"叶城\"},\"address\":{\"0\":\"东门捷径巷14号最\"},\"legalAddress\":{\"0\":\"长沙市芙蓉区东门捷径巷14号\"},\"policy\":{\"0\":\"分店无免费停车场，如需停车，可将车辆停至周边停车场，谢谢！thanks12叶城\"},\"coordinate\":{\"0\":\"113.087559165955230000000000000000,28.251818487944462000000000000000\"},\"isPrivilegeMemberHotel\":\"0\",\"preSaleStartDate\":\"2019-05-13 00:00:00\",\"preSaleEndDate\":\"2019-05-13 00:00:00\",\"canCheckInDate\":\"2019-05-13 17:00:00\",\"preSaleValid\":\"0\",\"isPerfectEnglish\":\"0\",\"isBreakfast\":\"0\",\"score\":\"2.5\",\"entireCount\":\"25\",\"goodScore\":\"60%\",\"isSesameCredit\":1,\"isDeposit\":1,\"depositAmount\":\"100\",\"upgradeType\":null,\"transferProjectId\":null,\"transferInnId\":null,\"transferInnNameCn\":null,\"projectId\":\"731009\",\"certificateType\":null,\"paymentMethod\":null}}";
		System.out.println("待加密字符串===" + dataStr);

		// 加密
		String encryptStr = SecureUtil.aes(secretKeyByte).encryptBase64(dataStr);
		System.out.println("AES加密===" + encryptStr);

		// 解密
		String decryptStr = SecureUtil.aes(secretKeyByte).decryptStr(encryptStr);
		System.out.println("AES解密===" + decryptStr);

		Assert.assertNotEquals(dataStr, encryptStr);
		Assert.assertNotEquals(encryptStr, decryptStr);

		// 解密后等于原文
		Assert.assertEquals(dataStr, decryptStr);
	}

	@Test
	public void desCrypto() {
		/** 默认的AES加密方式：AES/ECB/PKCS5Padding */
		String algorithm = "DES/ECB/PKCS5Padding";
		// String algorithm = SymmetricAlgorithm.DES.getValue();

		// 指定密钥字符串
		String originalKey = "12345678abc";

		// byte数组密钥
		SecretKey desSecretKey = SecureUtil.generateDESKey(algorithm, originalKey.getBytes());
		byte[] secretKeyByte = desSecretKey.getEncoded();

		System.out.println("DES密钥(byte[])===" + secretKeyByte);
		System.out.println("DES密钥(base64String)===" + Base64.encode(secretKeyByte));

		// 待加密字符串
		String dataStr = "{\"code\":\"0\",\"msg\":\"成功\",\"data\":{\"innId\":\"128\",\"chainCode\":\"128\",\"businessType\":\"0\",\"officeCenterType\":\"23\",\"supportPaymentMode\":null,\"forensicCode\":null,\"status\":\"1\",\"innType\":\"0\",\"starType\":\"-1\",\"recommandStarType\":\"0\",\"medalType\":\"5\",\"startFloor\":\"11,13,18-20\",\"endFloor\":\"20\",\"totalRoom\":\"46\",\"brandCode\":\"1\",\"innPhone\":\"123456789012345678901234567890\",\"innEmail\":\"123456@12.cn\",\"innFax\":\"123456\",\"supportPayOnline\":null,\"bookFlag\":\"1\",\"supportForeignGuest\":\"1\",\"valueAddedInvoice\":\"0\",\"chooseRoomSwitch\":\"1\",\"smartHotel\":\"1\",\"openDate\":\"2008-02-29\",\"closeDate\":null,\"ifsync\":\"1\",\"saleDepartId\":\"128\",\"mainPerson\":\"\",\"chineseInfoFull\":\"0\",\"englishInfoFull\":\"0\",\"auditStatus\":\"1\",\"mainPhone\":\"18521738707\",\"valid\":\"1\",\"createDateTime\":\"2018-05-18 10:15:37.0\",\"bookingInvoice\":\"1\",\"invoiceType\":\"2\",\"homeLink\":null,\"crsCode\":\"\",\"pmsCode\":null,\"roomSwitchFlag\":\"1\",\"smoking\":\"1\",\"pullRoomFlag\":\"1\",\"mainEmail\":\"\",\"decorationDate\":\"2019-08-01\",\"elevatorNum\":\"0\",\"meetingRoomNum\":\"0\",\"meetingRoomAccommodates\":\"0\",\"nonSmokingRoomsNum\":\"0\",\"maxCheckIn\":null,\"settlementCurrency\":\"CNY\",\"panoramaImage\":null,\"zipCode\":\"123456\",\"checkInTime\":\"14:00\",\"checkOutTime\":\"12:00\",\"timeZone\":\"GMT+8\",\"pets\":\"0\",\"allowMinors\":\"0\",\"innLevel\":\"0\",\"morningRoom\":\"1\",\"sourceType\":\"7days\",\"countryCode\":\"AR01438\",\"provinceCode\":\"AR04072\",\"cityCode\":\"AR03026\",\"secondCityCode\":\"AR03026\",\"districtCode\":\"AR02145\",\"pmsSourceType\":\"7days\",\"isSupportGuideDogPolicy\":\"1\",\"groupCode\":\"53\",\"diamondRating\":\"5\",\"videoUrl\":\"http://beyond.3dnest.cn/play/?m=zq_hpxed_4&from=singlemessage&isappinstalled=0\",\"vrVideoUrl\":null,\"innName\":{\"0\":\"7天酒店·长沙定王台省人民医院店\"},\"innShortName\":{\"0\":\"7tjd·zsdwtsrmyyd\"},\"innNamePinYin\":{\"0\":\"7tianjiudian·zhangshadingwangtaishengrenminyiyuandian\"},\"salutatory\":{\"0\":\"welcome to hunan\"},\"guide\":{\"0\":\"353543\"},\"countryName\":{\"0\":\"中国\"},\"provinceName\":{\"0\":\"湖南\"},\"cityName\":{\"0\":\"长沙\"},\"secondCityName\":{\"0\":\"长沙\"},\"districtName\":{\"0\":\"芙蓉区\"},\"brandName\":{\"0\":\"7天酒店\"},\"groupName\":{\"0\":\"铂涛集团\"},\"description\":{\"0\":\"叶城\"},\"address\":{\"0\":\"东门捷径巷14号最\"},\"legalAddress\":{\"0\":\"长沙市芙蓉区东门捷径巷14号\"},\"policy\":{\"0\":\"分店无免费停车场，如需停车，可将车辆停至周边停车场，谢谢！thanks12叶城\"},\"coordinate\":{\"0\":\"113.087559165955230000000000000000,28.251818487944462000000000000000\"},\"isPrivilegeMemberHotel\":\"0\",\"preSaleStartDate\":\"2019-05-13 00:00:00\",\"preSaleEndDate\":\"2019-05-13 00:00:00\",\"canCheckInDate\":\"2019-05-13 17:00:00\",\"preSaleValid\":\"0\",\"isPerfectEnglish\":\"0\",\"isBreakfast\":\"0\",\"score\":\"2.5\",\"entireCount\":\"25\",\"goodScore\":\"60%\",\"isSesameCredit\":1,\"isDeposit\":1,\"depositAmount\":\"100\",\"upgradeType\":null,\"transferProjectId\":null,\"transferInnId\":null,\"transferInnNameCn\":null,\"projectId\":\"731009\",\"certificateType\":null,\"paymentMethod\":null}}";
		System.out.println("待加密字符串===" + dataStr);

		// 加密
		String encryptStr = SecureUtil.des(secretKeyByte).encryptBase64(dataStr);
		System.out.println("DES加密===" + encryptStr);

		// 解密
		String decryptStr = SecureUtil.des(secretKeyByte).decryptStr(encryptStr);
		System.out.println("DES解密===" + decryptStr);

		Assert.assertNotEquals(dataStr, encryptStr);
		Assert.assertNotEquals(encryptStr, decryptStr);

		// 解密后等于原文
		Assert.assertEquals(dataStr, decryptStr);
	}

	/**   
	 *   对称算法加解密
	 */
	@Test
	public void symmetricCrypto() {
		// 算法
		String algorithm = "DES";
		Set<String> algorithmSets = Lists.newArrayList(SymmetricAlgorithm.values()).stream().map(SymmetricAlgorithm::getValue).collect(Collectors.toSet());
		if (!algorithmSets.contains(algorithm)) {
			System.out.println("对称加解密输入的算法有误！");
		}

		// 密钥
		String keyBase64 = "MTIzNDU2Nzg=";
		byte[] key = SecureUtil.decode(keyBase64);
		SymmetricCrypto symmetric = new SymmetricCrypto(algorithm, key);
		String originData = "jJgWeDTN7Wc=";
		String cryptoStr = symmetric.encryptBase64(originData);
		String deryptoStr = symmetric.decryptStr(cryptoStr);

		System.out.println("对称算法加解密，algorithm=" + algorithm + "，加密后数据=" + cryptoStr + ",解密后数据：" + deryptoStr);

		Assert.assertNotEquals(originData, cryptoStr);
		Assert.assertNotEquals(cryptoStr, deryptoStr);

		// 解密后等于原文
		Assert.assertEquals(originData, deryptoStr);
	}

	/**   
	 *     非对称算法加解密
	 */
	@Test
	public void asymmetricCrypto() {
		// 公钥
		String publicKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxXASuVMBcOAETOTtvnv7MNOTqUCtuf3NkTVXOhQqXFxKEL04Y2rzyMwbhL3D/dnf8kJ8s2GK7sbn+yNQAEiZ+rBFh22nO575Zm2TGO/sX31ew9gH/AmpLMXno19saeEvdRCYjJfWzldwPRlKlde2od7r34q2FBzH4SZ9ASvCiVwIDAQAB";
		String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALFcBK5UwFw4ARM5O2+e/sw05OpQK25/c2RNVc6FCpcXEoQvThjavPIzBuEvcP92d/yQnyzYYruxuf7I1AASJn6sEWHbac7nvlmbZMY7+xffV7D2Af8CaksxeejX2xp4S91EJiMl9bOV3A9GUqV17ah3uvfirYUHMfhJn0BK8KJXAgMBAAECgYAwf6okBbboQMRCfnb7Se4A50HltPB7ccybE+6v33+K21tL3Cet8jqSvFNYRoHOyZV78gwk1jMBglMLEd2u+0edDUBZltpKJxR6Kh3DDceh9K/MELG39KNTKb8RfEGMquLj38ZHGuxdL1H6xZwABk7+e6fmJ0+x0Pq3KZIRMNBluQJBAN/wnSxfJ+X8U7dla5hlk/oSHst/rW2O1WV/wlXzpl0TU+/Z81TDFoHC/AuFU72EH+1HejSoqDQCVg3Au3Jx/0MCQQDKwDusmcIzN7LbsvENKxirHxOfjGipKpn3FfIQGH6oGuJmiYrPKZzPxVXq5TzGNhFaO+zihKr9UaiLMKkd5Y1dAkAP/BbcAfbRHc/D+YNSn32OjhiQog55EYb99b6jb/7iCe0l48LQvBQxMv/Wuq+diX7V6xI4DAnlnH0UAjvfEXANAkEAj2ecTZ6Lf1J8DWzplljPH+nhJU5YkJ5zPBKnnb7Vhu1NCR1rss9J/KMk+/mcHM4NQ/dyu1z+3CGvxpNqapz8eQJAQqKw3yMTBkbHyu3j1sHUB/oPZiIHEvRmB5kQwJtpiUYfRUtNaqIHmE2Qh8WUyM+eJNzdrltkGQJN5SUOjGxxsg==";

		// 算法
		String algorithm = AsymmetricAlgorithm.RSA.getValue();
		String originData = "wehotel";
		String crypto = null;
		// 公钥加密
		AsymmetricCrypto ac = new AsymmetricCrypto(algorithm, null, publicKeyBase64);
		crypto = ac.encryptBase64(originData, KeyType.PublicKey);

		// 私钥解密
		ac = new AsymmetricCrypto(algorithm, privateKey, null);
		String derypto = ac.decryptStr(crypto, KeyType.PrivateKey);
		System.out.println("非对称算法加解密，algorithm=" + algorithm + "，加解密后数据=" + crypto);

		// 解密后等于原文
		Assert.assertEquals(originData, derypto);
	}

	/**   
	 *     摘要算法加解密
	 */
	@Test
	public void digesterCrypto() {
		String agorithm = DigestAlgorithm.MD5.getValue();
		String originData = "wehotel";
		Digester digest = new Digester(agorithm);
		String digestHex = digest.digestHex(originData);
		System.out.println("摘要加密，agorithm=" + agorithm + "，加密后数据==" + digestHex);

	}

	@Test
	public void test() {
		// String algorithm = "DSA";
		// Set<String> algorithmSets =
		// Lists.newArrayList(DigestAlgorithm.values()).stream().map(DigestAlgorithm::getValue).collect(Collectors.toSet());
		// System.out.println(algorithmSets.contains(algorithm));
		String keyType = KeyType.PrivateKey.toString();
		System.out.println(keyType);
	}

	@Test
	public void generateKey() {
		// 生成AES默认随机密钥，使用默认算法=AES/ECB/PKCS5Padding，默认长度=128
		System.out.println("++++++++++++AES生成随机密钥++++++++++++++++++");
		String aesAlgorithm = SymmetricAlgorithm.AES.getValue();
		SecretKey aesSecretKey = SecureUtil.generateKey(aesAlgorithm);
		System.out.println("AES默认随机密钥(byte)===" + aesSecretKey.getEncoded());
		System.out.println("AES默认随机密钥(base64String)===" + Base64.encode(aesSecretKey.getEncoded()));
		System.out.println("");

		// 生成AES默认随机密钥，使用默认算法=DES/ECB/PKCS5Padding，默认长度=128
		System.out.println("++++++++++++DES生成随机密钥++++++++++++++++++");
		String desAlgorithm = SymmetricAlgorithm.DES.getValue();
		String desKey = "12345678abc12345678abc";// 只有前面8位对生成的密钥有效
		SecretKey desSecretKey = SecureUtil.generateDESKey(desAlgorithm, desKey.getBytes());
		System.out.println("DES默认随机密钥(byte)===" + desSecretKey.getEncoded());
		System.out.println("DES默认随机密钥(base64String)===" + Base64.encode(desSecretKey.getEncoded()));
		System.out.println("");

		// 生成RSA默认随机密钥
		String rsaAlgorithm = AsymmetricAlgorithm.RSA.getValue();
		KeyPair keyPair = SecureUtil.generateKeyPair(rsaAlgorithm);
		// 私钥
		PrivateKey privateKey = keyPair.getPrivate();
		System.out.println("RSA私钥==" + Base64.encode(privateKey.getEncoded()));
		// 公钥
		PublicKey publicKey = keyPair.getPublic();
		System.out.println("RSA公钥==" + Base64.encode(publicKey.getEncoded()));
		System.out.println("");

	}

	@Test
	public void keyTypeTest() {
		System.out.println("publicKey=" + KeyType.PublicKey.getValue());
		System.out.println("privateKey=" + KeyType.PrivateKey.getValue());
		System.out.println("scecretKey=" + KeyType.SecretKey.getValue());
	}

	@Test
	public void enumTest() {
		System.out.println(ParamsEnum.ALGORITHM.getName());
		System.out.println(ParamsEnum.ALGORITHM.toString());
	}

	@Test
	public void jsonPath() {
		String responseBody = "{\"code\":0,\"msg\":\"成功\",\"data\":{\"userId\":1234567,\"userName\":\"administator\",\"phone\":\"13111111111\",\"hotels\":[{\"innId\":\"128\",\"innName\":\"7天酒店·长沙定王台省人民医院店\"},{\"innId\":\"451\",\"innName\":\"7天酒店·广州琶洲会展赤岗地铁站店\"},{\"innId\":\"JJ65001\",\"innName\":\"锦江都城经典达华静安寺酒店\"}]}}";
		System.out.println("responseBody=" + responseBody);

		// Map<String, Object> resultMap = Maps.newHashMap();
		// resultMap.put("code", 0);
		// resultMap.put("msg", "成功");
		//
		// Map<String, Object> dataMap = Maps.newHashMap();
		// dataMap.put("userId", 1234567);
		// dataMap.put("userName", "admin1");
		// dataMap.put("phone", "1391111111");
		//
		// List<Map<String,Object>> hotelList=Lists.newArrayList();
		//
		// Map<String,Object> innMap1=Maps.newHashMap();
		// innMap1.put("innId", "128");
		// innMap1.put("innName", "7天酒店·长沙定王台省人民医院店");
		// hotelList.add(innMap1);
		// Map<String,Object> innMap2=Maps.newHashMap();
		// innMap2.put("innId", "451");
		// innMap2.put("innName", "7天酒店·广州琶洲会展赤岗地铁站店");
		// hotelList.add(innMap2);
		//
		// dataMap.put("hotels", hotelList);
		// resultMap.put("data", dataMap);
		//
		// String responseBody = JSON.toJSONString(resultMap);
		// System.out.println("responseBody=" + responseBody);

		DocumentContext dc = JsonPath.parse(responseBody);

		// 根据jsonPath筛选值
		String jsonPath = "$..hotels[0,1].['innName']";

		JsonPath p = JsonPath.compile(jsonPath);
		System.out.println("JsonPath=" + p);
//		String newBody = "fVV3dhnza9bYhVvTvMJ0Cr9Wi9X1A4vDDlKATQ36n6I";
		List<String> newBody = Lists.newArrayList("111","222");

		DocumentContext newdc = dc.set(p, newBody);
		System.out.println("responseBody=" + newdc.jsonString());
		// 更新值
		// = JSON.parseObject(responseBody, Map.class);
		// JSONPath.set(responseBody, "innId", newBody);
		// System.out.println("newBody=" + responseBody);
	}

}
