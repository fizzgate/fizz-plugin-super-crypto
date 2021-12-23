package we.plugin.crypto.bean;

import java.io.Serializable;

import org.springframework.util.StringUtils;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 *  
 * @author  lml.li
 * @date  2021-9-26 14:28:59
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class StateInfo<T> implements Serializable {

	private static final long serialVersionUID = 75376126893268982L;

	private String code;
	private String msg;
	private T data;

	/**
	 * 成功
	 * @return
	 */
	public static <T> StateInfo<T> success() {
		return success(null);
	}

	/**
	 * 成功
	 * @param data
	 * @return
	 */
	public static <T> StateInfo<T> success(T data) {
		return new StateInfo<>(StateCode.SUCCESS.getCode(), StateCode.SUCCESS.getName(), data);
	}

	/**
	 * 失败
	 * @return
	 */
	public static <T> StateInfo<T> error(String message) {
		return StateInfo.error(null, message);
	}

	/**
	 * 失败，自定义错误码
	 * @return
	 */
	public static <T> StateInfo<T> error(String code, String message) {
		return new StateInfo<>(StringUtils.hasText(code) ? code : StateCode.FAILURE.getCode(), message, null);
	}
}
