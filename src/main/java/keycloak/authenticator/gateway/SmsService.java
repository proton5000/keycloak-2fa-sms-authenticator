package keycloak.authenticator.gateway;

import java.io.IOException;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
public interface SmsService {
	void send(String phoneNumber, String message) throws IOException;
}
