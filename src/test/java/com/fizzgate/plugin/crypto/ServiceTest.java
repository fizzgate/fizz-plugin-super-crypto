package com.fizzgate.plugin.crypto;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONPath;

import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import com.fizzgate.plugin.crypto.bean.CommonConstant;
import com.fizzgate.plugin.crypto.bean.StateCode;
import com.fizzgate.plugin.crypto.bean.StateInfo;
import com.fizzgate.plugin.crypto.service.CryptoService;

public class ServiceTest {

	CryptoService cryptoService = new CryptoService();

	@Rule
	public ExpectedException expectEx = ExpectedException.none();

	/**   
	 * 对称算法加解密
	 */
	@Test
	public void symmetricEnDecrypt() {
		String algorithm = "AES";
		String keyBase64 = "3frPWviKGx6gCD1KDnFcTw==";
		String originData = "{\"account\":\"admin\",\"password\":\"test012\",\"generateToken\":true}";

		// 加密
		StateInfo<String> encryptResult = cryptoService.symmetricCrypto(algorithm, keyBase64, originData, CommonConstant.ENCRYPT_MODE);
		System.out.println("加密结果:" + encryptResult);

		Assert.assertNotNull(encryptResult);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), encryptResult.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(encryptResult.getData()));

		// 解密
		StateInfo<String> decryptResult = cryptoService.symmetricCrypto(algorithm, keyBase64, encryptResult.getData(), CommonConstant.DECRYPT_MODE);
		System.out.println("解密结果:" + decryptResult);

		Assert.assertNotNull(decryptResult);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), decryptResult.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(decryptResult.getData()));

		// 解密后等于原文
		Assert.assertEquals(originData, decryptResult.getData());
	}

	@Test
	public void testSymmetricParamError() {

		String wrongAlgorithm = "NotExist";
		String correctAlgorithm = "AES";
		String correctKey = "3frPWviKGx6gCD1KDnFcTw==";
		String originData = "{\"account\":\"admin\",\"password\":\"test012\",\"generateToken\":true}";

		// 参数空
		StateInfo<String> result = cryptoService.symmetricCrypto(correctAlgorithm, null, originData, CommonConstant.ENCRYPT_MODE);
		Assert.assertNotNull(result);
		Assert.assertEquals(StateCode.PARAM_MISS.getCode(), result.getCode());

		result = cryptoService.symmetricCrypto(correctAlgorithm, correctKey, null, CommonConstant.ENCRYPT_MODE);
		Assert.assertNotNull(result);
		Assert.assertEquals(StateCode.PARAM_MISS.getCode(), result.getCode());

		result = cryptoService.symmetricCrypto(null, correctKey, originData, CommonConstant.ENCRYPT_MODE);
		Assert.assertNotNull(result);
		Assert.assertEquals(StateCode.PARAM_ERROR.getCode(), result.getCode());

		// 算法不支持
		result = cryptoService.symmetricCrypto(wrongAlgorithm, correctKey, originData, CommonConstant.ENCRYPT_MODE);
		Assert.assertNotNull(result);
		Assert.assertEquals(StateCode.PARAM_ERROR.getCode(), result.getCode());
	}

	@Test
	public void testSymmetricException() {
		String correctAlgorithm = "AES";
		String correctKey = "3frPWviKGx6gCD1KDnFcTw==";
		String wrongKey = correctKey + "errorkey";
		String originData = "{\"account\":\"admin\",\"password\":\"test012\",\"generateToken\":true}";

//		// key 错误
//		expectEx.expect(CryptoException.class);
//		expectEx.expectCause(Matchers.<InvalidKeyException> any(InvalidKeyException.class));
//		cryptoService.symmetricCrypto(correctAlgorithm, wrongKey, originData, CommonConstant.ENCRYPT_MODE);
	}

	/**   
	 *  非对称算法加密         
	 */
	@Test
	public void asymmetricEnDecrypt() {
		String algorithm = "RSA";
		String originData = "{\"account\":\"admin\",\"password\":\"test012\",\"generateToken\":true}";
		// 公钥
		String pubKeyBase64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxXASuVMBcOAETOTtvnv7MNOTqUCtuf3NkTVXOhQqXFxKEL04Y2rzyMwbhL3D/dnf8kJ8s2GK7sbn+yNQAEiZ+rBFh22nO575Zm2TGO/sX31ew9gH/AmpLMXno19saeEvdRCYjJfWzldwPRlKlde2od7r34q2FBzH4SZ9ASvCiVwIDAQAB";
		// 私钥
		String priKeyBase64 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALFcBK5UwFw4ARM5O2+e/sw05OpQK25/c2RNVc6FCpcXEoQvThjavPIzBuEvcP92d/yQnyzYYruxuf7I1AASJn6sEWHbac7nvlmbZMY7+xffV7D2Af8CaksxeejX2xp4S91EJiMl9bOV3A9GUqV17ah3uvfirYUHMfhJn0BK8KJXAgMBAAECgYAwf6okBbboQMRCfnb7Se4A50HltPB7ccybE+6v33+K21tL3Cet8jqSvFNYRoHOyZV78gwk1jMBglMLEd2u+0edDUBZltpKJxR6Kh3DDceh9K/MELG39KNTKb8RfEGMquLj38ZHGuxdL1H6xZwABk7+e6fmJ0+x0Pq3KZIRMNBluQJBAN/wnSxfJ+X8U7dla5hlk/oSHst/rW2O1WV/wlXzpl0TU+/Z81TDFoHC/AuFU72EH+1HejSoqDQCVg3Au3Jx/0MCQQDKwDusmcIzN7LbsvENKxirHxOfjGipKpn3FfIQGH6oGuJmiYrPKZzPxVXq5TzGNhFaO+zihKr9UaiLMKkd5Y1dAkAP/BbcAfbRHc/D+YNSn32OjhiQog55EYb99b6jb/7iCe0l48LQvBQxMv/Wuq+diX7V6xI4DAnlnH0UAjvfEXANAkEAj2ecTZ6Lf1J8DWzplljPH+nhJU5YkJ5zPBKnnb7Vhu1NCR1rss9J/KMk+/mcHM4NQ/dyu1z+3CGvxpNqapz8eQJAQqKw3yMTBkbHyu3j1sHUB/oPZiIHEvRmB5kQwJtpiUYfRUtNaqIHmE2Qh8WUyM+eJNzdrltkGQJN5SUOjGxxsg==";

		// 公钥加密
		StateInfo<String> encryptResult = cryptoService.asymmetricCrypto(algorithm, pubKeyBase64, originData, CommonConstant.ENCRYPT_MODE, KeyType.PublicKey);
		System.out.println("公钥加密结果:" + encryptResult);

		Assert.assertNotNull(encryptResult);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), encryptResult.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(encryptResult.getData()));

		// 私钥解密
		StateInfo<String> decryptResult = cryptoService.asymmetricCrypto(algorithm, priKeyBase64, encryptResult.getData(), CommonConstant.DECRYPT_MODE, KeyType.PrivateKey);
		System.out.println("私钥解密结果:" + decryptResult);

		Assert.assertNotNull(decryptResult);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), decryptResult.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(decryptResult.getData()));

		// 解密后等于原文
		Assert.assertEquals(originData, decryptResult.getData());

		// 私钥加密
		encryptResult = cryptoService.asymmetricCrypto(algorithm, priKeyBase64, originData, CommonConstant.ENCRYPT_MODE, KeyType.PrivateKey);
		System.out.println("私钥加密结果:" + encryptResult);
		Assert.assertNotNull(encryptResult);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), encryptResult.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(encryptResult.getData()));

		// 公钥解密
		decryptResult = cryptoService.asymmetricCrypto(algorithm, pubKeyBase64, encryptResult.getData(), CommonConstant.DECRYPT_MODE, KeyType.PublicKey);
		System.out.println("私钥解密结果:" + decryptResult);

		Assert.assertNotNull(decryptResult);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), decryptResult.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(decryptResult.getData()));

		// 解密后等于原文
		Assert.assertEquals(originData, decryptResult.getData());
	}

	/**   
	 * 摘要算法加密
	 */
	@Test
	public void digester() {
		String algorithm = "MD5";
		String originData = "{\"account\":\"admin\",\"password\":\"test012\",\"generateToken\":true}";
		StateInfo<String> result = cryptoService.digester(algorithm, originData);
		System.out.println(result);

		Assert.assertNotNull(result);
		Assert.assertEquals(StateCode.SUCCESS.getCode(), result.getCode());
		Assert.assertTrue(StringUtils.isNotBlank(result.getData()));
	}

	@Test
	public void aesTest() {
		String decryptStr = "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";
		String keyBase64 = "WAYO2FvEp00Qw/CWAlI2iA==";
		String algorithm = "AES";
		StateInfo<String> encryptResult = cryptoService.symmetricCrypto(algorithm, keyBase64, decryptStr, CommonConstant.DECRYPT_MODE);
		System.out.println("解密结果:" + encryptResult);
	}

	@Test
	public void json() {
		String originJson = "{\"id\":4,\"isDeleted\":0,\"gatewayGroups\":[\"default\"],\"service\":\"we-reward-new\",\"fizzMethod\":\"POST\",\"path\":\"/**\",\"exactMatch\":false,\"backendPath\":\"/we-reward-new/{$1}\",\"httpHostPorts\":[\"http://localhost:8080\"],\"access\":\"a\",\"pluginConfigs\":[{\"plugin\":\"requestBodyPlugin\"},{\"plugin\":\"superCryptoPlugin\",\"config\":{\"mode\":1,\"secretKey\":\"WAYO2FvEp00Qw/CWAlI2iA==\",\"cryptoType\":\"requestCrypt\",\"keyType\":3,\"algorithm\":\"AES\"}}],\"checkApp\":false,\"timeout\":0,\"proxyMode\":3}";
		Object json = JSON.parse(originJson);
		// if (json instanceof JSONObject) {
		// JSONObject jsonObject = (JSONObject) json;
		// } else if (json instanceof JSONArray) {
		// JSONArray jsonArray = (JSONArray) json;
		// }

		String path = "$..isDeleted";
		// 筛选值
		String pathValue = JSONPath.eval(json, path).toString();
		StateInfo<String> result = cryptoService.symmetricCrypto("AES", "WAYO2FvEp00Qw/CWAlI2iA==", pathValue, 1);
		if (ObjectUtil.isNotEmpty(result) && !StrUtil.equals(result.getCode(), StateCode.SUCCESS.getCode())) {
			System.out.println("加解密异常");
		}
		// 更新值
		boolean isSuc = JSONPath.set(json, path, result.getData());
		if (isSuc) {
			String newJson = JSON.toJSONString(json);
			System.out.println("originJson=" + originJson);
			System.out.println("path=" + path);
			System.out.println("newJson=" + newJson);
		}

	}
}
