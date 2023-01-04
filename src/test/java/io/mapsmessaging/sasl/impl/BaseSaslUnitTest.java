package io.mapsmessaging.sasl.impl;

import io.mapsmessaging.security.MapsSecurityProvider;
import io.mapsmessaging.security.sasl.IdentityLookup;
import io.mapsmessaging.security.sasl.impl.htpasswd.HashType;
import java.security.Security;
import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;

@SuppressWarnings("java:S2187") // Ignore the no test rule

public class BaseSaslUnitTest {

  @BeforeAll
  static void register(){
    Security.insertProviderAt(new MapsSecurityProvider(), 1);
  }

  protected SaslServer saslServer;
  protected SaslClient saslClient;

  protected void createClient(String username,
      String password,
      HashType hashType,
      String[] mechanism,
      String protocol,
      String authorizationId,
      String serverName,
      Map<String, String> props) throws SaslException {
    ClientCallbackHandler clientHandler = new ClientCallbackHandler(username, password, hashType, serverName);
    saslClient = Sasl.createSaslClient(mechanism, authorizationId, protocol, serverName, props, clientHandler);
  }

  protected void createServer(IdentityLookup identityLookup, String mechanism, String protocol, String serverName, Map<String, String> props) throws SaslException {
    saslServer =  Sasl.createSaslServer(mechanism, protocol, serverName, props, new ServerCallbackHandler(serverName, identityLookup));
  }

  protected void runAuth() throws SaslException {
    byte[] challenge;
    byte[] response = new byte[0];

    while (!saslClient.isComplete() && !saslServer.isComplete()) {
      challenge = saslServer.evaluateResponse(response);
      response = saslClient.evaluateChallenge(challenge);
    }
    if (response != null) {
      saslServer.evaluateResponse(response);
    }
  }

  @AfterEach
  public void tearDown() throws SaslException {
    if(saslClient != null) saslClient.dispose();
    if(saslServer != null) saslServer.dispose();
  }


}
