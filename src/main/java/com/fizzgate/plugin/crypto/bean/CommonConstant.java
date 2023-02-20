package com.fizzgate.plugin.crypto.bean;

/**
 *  通用常量
 * @author  lml.li
 * @date  2021-9-29 10:48:22
 */
public class CommonConstant {

	// 加密
	public final static int ENCRYPT_MODE = 1;

	// 解密
	public final static int DECRYPT_MODE = 2;

	// 对称算法
	public final static int SYMMETRIC = 1;

	// 非对称算法
	public final static int ASYMMETRIC = 2;

	// 摘要算法
	public final static int DIGESTER = 3;

	public final static String REQUEST_CRYPT = "requestCrypt";

	public final static String RESPONSE_CRYPT = "responseCrypt";
	
	public final static String REQUEST_HEADERS_CRYPT = "requestHeadersCrypt";
	
	public final static String RESPONSE_HEADERS_CRYPT = "responseHeadersCrypt";
	
	//公钥
	public final static int KEY_TYPE_PUBLIC = 1;

	//私钥
	public final static int KEY_TYPE_PRIVATE = 2;
	
	//密钥
	public final static int KEY_TYPE_SECRET = 3;
}
