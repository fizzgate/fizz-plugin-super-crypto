package we.plugin.crypto.service;

import java.text.MessageFormat;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;

import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricAlgorithm;
import cn.hutool.crypto.asymmetric.AsymmetricCrypto;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.digest.DigestAlgorithm;
import cn.hutool.crypto.digest.Digester;
import cn.hutool.crypto.symmetric.SymmetricAlgorithm;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import lombok.extern.slf4j.Slf4j;
import we.plugin.crypto.bean.CommonConstant;
import we.plugin.crypto.bean.StateCode;
import we.plugin.crypto.bean.StateInfo;

/**
 *  加解密业务处理
 * @author  lml.li
 * @date  2021-9-26 14:29:05
 */
@Service
@Slf4j
public class CryptoService {

	/**   
	 * 对称算法加解密
	 * @param algorithm 算法类型：AES，DES，ARCFOUR，Blowfish，DESede，RC2
	 * 参考：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator
	 * @param keyBase64	密钥(base64字符串)
	 * @param originData 原始数据
	 * @param mode 1-加密，2-解密
	 * @return 加解密后数据       
	 */
	public StateInfo<String> symmetricCrypto(String algorithm, String keyBase64, String originData, int mode) {
		Set<String> algorithmSets = Lists.newArrayList(SymmetricAlgorithm.values()).stream().map(SymmetricAlgorithm::getValue).collect(Collectors.toSet());
		if (!algorithmSets.contains(algorithm)) {
			return StateInfo.error(StateCode.PARAM_ERROR.getCode(), MessageFormat.format(StateCode.PARAM_ERROR.getName(), "algorithm"));
		}
		if (StrUtil.isBlank(keyBase64)) {
			return StateInfo.error(StateCode.PARAM_MISS.getCode(), MessageFormat.format(StateCode.PARAM_MISS.getName(), "keyBase64"));
		}
		if (StrUtil.isBlank(originData)) {
			return StateInfo.error(StateCode.PARAM_MISS.getCode(), MessageFormat.format(StateCode.PARAM_MISS.getName(), "data"));
		}

		String cryptoStr = null;
		try {
			byte[] key = SecureUtil.decode(keyBase64);
			SymmetricCrypto symmetric = new SymmetricCrypto(algorithm, key);

			cryptoStr = null;
			// 加密
			if (mode == CommonConstant.ENCRYPT_MODE) {
				cryptoStr = symmetric.encryptBase64(originData);
			}
			// 解密
			if (mode == CommonConstant.DECRYPT_MODE) {
				cryptoStr = symmetric.decryptStr(originData);
			}
		} catch (Exception e) {
			log.error("对称算法加解密出现异常，algorithm={}，keyBase64={}，originData={}，mode={}", algorithm, keyBase64, originData, mode);
			return StateInfo.error(StateCode.CRYPTO_ERROR.getCode(), StateCode.CRYPTO_ERROR.getName());
		}
		log.info("对称算法加解密，algorithm={}，加解密后数据={}", algorithm, cryptoStr);
		return StateInfo.success(cryptoStr);
	}

	/**   
	 * 非对称算法加解密
	 * @param algorithm 算法类型：RSA，RSA/ECB/PKCS1Padding，RSA/ECB/NoPadding，RSA/None/NoPadding
	 * 参考：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
	 * @param keyBase64	密钥(base64字符串)，加密操作时为公钥，解密操作时为私钥
	 * @param originData 原始数据
	 * @param mode 模式 1-加密，2-解密
	 * @param keyType 密钥类型 1-公钥，2-私钥，3-密钥
	 * @return 加解密后数据       
	 */
	public StateInfo<String> asymmetricCrypto(String algorithm, String keyBase64, String originData, int mode, KeyType keyType) {

		Set<String> algorithmSets = Lists.newArrayList(AsymmetricAlgorithm.values()).stream().map(AsymmetricAlgorithm::getValue).collect(Collectors.toSet());
		if (!algorithmSets.contains(algorithm)) {
			return StateInfo.error(StateCode.PARAM_ERROR.getCode(), MessageFormat.format(StateCode.PARAM_ERROR.getName(), "algorithm"));
		}
		if (StrUtil.isBlank(keyBase64)) {
			return StateInfo.error(StateCode.PARAM_MISS.getCode(), MessageFormat.format(StateCode.PARAM_MISS.getName(), "keyBase64"));
		}
		if (StrUtil.isBlank(originData)) {
			return StateInfo.error(StateCode.PARAM_MISS.getCode(), MessageFormat.format(StateCode.PARAM_MISS.getName(), "data"));
		}
		if (keyType == null) {
			return StateInfo.error(StateCode.PARAM_MISS.getCode(), MessageFormat.format(StateCode.PARAM_MISS.getName(), "keyType"));
		}

		String cryptoStr = null;
		try {
			AsymmetricCrypto ac = null;
			if (keyType == KeyType.PublicKey) {
				ac = new AsymmetricCrypto(algorithm, null, keyBase64);
			}
			if (keyType == KeyType.PrivateKey) {
				ac = new AsymmetricCrypto(algorithm, keyBase64, null);
			}

			// 加密
			if (mode == CommonConstant.ENCRYPT_MODE) {
				cryptoStr = ac.encryptBase64(originData, keyType);
			}

			// 解密
			if (mode == CommonConstant.DECRYPT_MODE) {
				cryptoStr = ac.decryptStr(originData, keyType);
			}
		} catch (Exception e) {
			log.error("非对称算法加解密出现异常，algorithm={}，keyBase64={}，keyType={}, originData={}，mode={}", algorithm, keyBase64, keyType, originData, mode);
			return StateInfo.error(StateCode.CRYPTO_ERROR.getCode(), StateCode.CRYPTO_ERROR.getName());
		}
		log.info("非对称算法加解密，algorithm={}，加解密后数据={}", algorithm, cryptoStr);
		return StateInfo.success(cryptoStr);
	}

	/**   
	 * 摘要算法加密(消息摘要算法是不可逆的，理论上无法通过反向运算取得原数据内容，因此它通常只能被用来做数据完整性验证)
	 * @param algorithm 算法：MD2，MD5，SHA-1，SHA-256，SHA-384，SHA-512
	 * 参考：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#MessageDigest
	 * @param originData
	 * @return          
	 */
	public StateInfo<String> digester(String algorithm, String originData) {
		StateInfo<String> stateInfo = new StateInfo<String>(StateCode.SUCCESS.getCode(), StateCode.SUCCESS.getName(), null);

		Set<String> algorithmSets = Lists.newArrayList(DigestAlgorithm.values()).stream().map(DigestAlgorithm::getValue).collect(Collectors.toSet());
		if (!algorithmSets.contains(algorithm)) {
			return StateInfo.error(StateCode.PARAM_ERROR.getCode(), MessageFormat.format(StateCode.PARAM_ERROR.getName(), "algorithm"));
		}
		if (StrUtil.isBlank(originData)) {
			return StateInfo.error(StateCode.PARAM_MISS.getCode(), MessageFormat.format(StateCode.PARAM_MISS.getName(), "data"));
		}

		String digestHex = null;
		try {
			Digester digest = new Digester(algorithm);
			digestHex = digest.digestHex(originData);
			stateInfo.setData(digestHex);
		} catch (Exception e) {
			log.error("摘要算法加解密出现异常，algorithm={}，originData={}", algorithm, originData);
			return StateInfo.error(StateCode.CRYPTO_ERROR.getCode(), StateCode.CRYPTO_ERROR.getName());
		}
		log.info("摘要算法加解密，algorithm={}，加解密后数据={}", algorithm, digestHex);
		return StateInfo.success(digestHex);
	}
}
