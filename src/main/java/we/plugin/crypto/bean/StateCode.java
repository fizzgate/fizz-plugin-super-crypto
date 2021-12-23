package we.plugin.crypto.bean;

import java.util.Arrays;

/**
 *  
 * @author  lml.li
 * @date  2021-9-26 14:41:10
 */
public enum StateCode {
	
	SUCCESS("1", "请求成功"),
	FAILURE("-1", "失败"),
	PARAM_MISS("1001", "缺失参数: {0}"),
	PARAM_FORMAT_ERROR("1002", "参数格式错误: 参数{0}, 类型{1}"),
	PARAM_ERROR("1003", "传入的参数有误: {0}"),
	CRYPTO_ERROR("1004", "加解密失败");
	
	private String code;
	private String name;

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	private StateCode(String code, String name) {
		this.code = code;
		this.name = name;
	}

	/**   
	 * 通过code获取name
	 * @param code
	 * @return          
	 */
	public static String getName(String code) {
		return Arrays.stream(StateCode.values())
							.filter(type -> type != null && code != null && code.equals(type.code))
			                .findFirst()
			                .map(type -> type.name)
			                .orElse(null);
	}
}
