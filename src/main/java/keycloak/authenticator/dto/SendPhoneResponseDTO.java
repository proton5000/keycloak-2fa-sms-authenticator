package keycloak.authenticator.dto;

public class SendPhoneResponseDTO {


	public SendPhoneResponseDTO() {
	}

	public SendPhoneResponseDTO(Boolean result, String phone, String error, String error_description) {
		this.result = result;
		this.phone = phone;
		this.error = error;
		this.error_description = error_description;
	}

	Boolean result;
	String phone;
	String error;
	String error_description;

	public Boolean getResult() {
		return result;
	}

	public void setResult(Boolean result) {
		this.result = result;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public String getError_description() {
		return error_description;
	}

	public void setError_description(String error_description) {
		this.error_description = error_description;
	}

	@Override
	public String toString() {
		return "SendPhoneResponseDTO{" +
			"result=" + result +
			", phone='" + phone + '\'' +
			", error='" + error + '\'' +
			", error_description='" + error_description + '\'' +
			'}';
	}
}
