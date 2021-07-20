package keycloak.authenticator;

import keycloak.authenticator.dto.ValidateCodeResponseDTO;
import keycloak.authenticator.gateway.SmsServiceFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.core.Response;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
public class SmsAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-sms.ftl";

	private static final String VALIDATE_OTP_URL = "https://oauth2.varus.ua/rest/otp/validate";

	private static final Logger LOG = Logger.getLogger(SmsAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();

		String mobileNumber = user.getFirstAttribute("mobile_number");
		// mobileNumber of course has to be further validated on proper format, country code, ...

		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		authSession.setAuthNote("phone", mobileNumber);

		authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

		try {
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");

			String code;
			// added the simulation code to the session if the simulation mode enabled
			if (Boolean.parseBoolean(config.getConfig().getOrDefault("simulation", "false"))) {
				code = String.valueOf(generateRandomDigits(Integer.parseInt(config.getConfig().get("length"))));
				authSession.setAuthNote("simulationCode", code);
			} else {
				code = new String(new char[Integer.parseInt(config.getConfig().get("length"))]).replace("\0", "*");
			}

			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

			context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", e.getMessage())
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	public static int generateRandomDigits(int n) {
		int m = (int) Math.pow(10, n - 1);
		return m + new Random().nextInt(9 * m);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		String ttl = authSession.getAuthNote("ttl");

		if (enteredCode == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		boolean isValid;

		// if the simulation mode enabled chek the simulationCode from session, if no send request for validate entered code by user
		if (Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().getOrDefault("simulation", "false"))) {
			isValid = enteredCode.equals(authSession.getAuthNote("simulationCode"));
		} else {
			ResponseEntity<ValidateCodeResponseDTO> response = validateOtp(authSession.getAuthNote("phone"), enteredCode);
			if (!response.getStatusCode().equals(HttpStatus.OK)) {
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return;
			}
			isValid = (Objects.nonNull(response.getBody())) ? response.getBody().getResult() : false;
		}

		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("smsAuthCodeInvalid").createForm(TPL_CODE));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return user.getFirstAttribute("mobile_number") != null;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

	private ResponseEntity<ValidateCodeResponseDTO> validateOtp(String phone, String enteredCode) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("phone", phone);
		map.add("otp", enteredCode);

		HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

		ResponseEntity<ValidateCodeResponseDTO> response =
			new RestTemplate().exchange(VALIDATE_OTP_URL, HttpMethod.POST, entity, ValidateCodeResponseDTO.class);

		LOG.info("Validate otp code. Response:" + response.getBody());

		return response;
	}

}
