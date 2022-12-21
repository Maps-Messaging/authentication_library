package io.mapsmessaging.sasl.provider.scram;

import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

public class ScramSaslClientFactory implements SaslClientFactory {

  @Override
  public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
      throws SaslException {
    return new ScramSaslClient(mechanisms, authorizationId, protocol, serverName, props, cbh);
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[0];
  }
}
