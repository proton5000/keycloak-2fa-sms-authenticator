package keycloak.authenticator.dto;

public class ValidateCodeResponseDTO {

	public ValidateCodeResponseDTO() {
	}

	public ValidateCodeResponseDTO(String phone, Boolean result, String fullName, String personalNumber,
								   String email, String company, String inn, String error, String error_description) {
		this.phone = phone;
		this.result = result;
		this.fullName = fullName;
		this.personalNumber = personalNumber;
		this.email = email;
		this.company = company;
		this.inn = inn;
		this.error = error;
		this.error_description = error_description;
	}

	String phone;
	Boolean result;
	String fullName;
	String personalNumber;
	String email;
	String company;
	String inn;

	String error;
	String error_description;

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public Boolean getResult() {
		return result;
	}

	public void setResult(Boolean result) {
		this.result = result;
	}

	public String getFullName() {
		return fullName;
	}

	public void setFullName(String fullName) {
		this.fullName = fullName;
	}

	public String getPersonalNumber() {
		return personalNumber;
	}

	public void setPersonalNumber(String personalNumber) {
		this.personalNumber = personalNumber;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(String company) {
		this.company = company;
	}

	public String getInn() {
		return inn;
	}

	public void setInn(String inn) {
		this.inn = inn;
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
		return "ValidateCodeResponseDTO{" +
			"phone='" + phone + '\'' +
			", result=" + result +
			", fullName='" + fullName + '\'' +
			", personalNumber='" + personalNumber + '\'' +
			", email='" + email + '\'' +
			", company='" + company + '\'' +
			", inn='" + inn + '\'' +
			", error='" + error + '\'' +
			", error_description='" + error_description + '\'' +
			'}';
	}
}
