package we.plugin.crypto.bean;

public enum ParamsEnum {
	ALGORITHM("algorithm"), SECRET_KEY("secretKey"), CRYPTO_TYPE("cryptoType"), MODE("mode"), KEY_TYPE("keyType"), JSON_PATH("jsonPath");

	private String name;

	ParamsEnum(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

}
