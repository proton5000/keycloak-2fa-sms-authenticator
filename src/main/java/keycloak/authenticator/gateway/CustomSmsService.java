package keycloak.authenticator.gateway;

import keycloak.authenticator.dto.SendPhoneResponseDTO;
import org.jboss.logging.Logger;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
public class CustomSmsService implements SmsService {

	private final String senderId;

	private static final Logger LOG = Logger.getLogger(CustomSmsService.class);

	private static final String SEND_OTP_URL = "https://oauth2.varus.ua/rest/otp/send";

	CustomSmsService(Map<String, String> config) {
		senderId = config.get("senderId");
	}

	@Override
	public void send(String phoneNumber, String message) {
		LOG.info(String.format("The phone number is: %s", phoneNumber));
		sendOtp(phoneNumber);
		LOG.info(String.format("The sms message is: %s", message));
	}

	private void sendOtp(String mobileNumber) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("phone", mobileNumber);

		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

		LOG.info("Send otp code. Response: " + new RestTemplate()
			.exchange(SEND_OTP_URL, HttpMethod.POST, entity, SendPhoneResponseDTO.class).getBody());
	}

}
