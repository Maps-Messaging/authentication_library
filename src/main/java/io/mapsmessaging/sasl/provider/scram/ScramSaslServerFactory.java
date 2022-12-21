package io.mapsmessaging.sasl.provider.scram;

import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

public class ScramSaslServerFactory implements SaslServerFactory {

  @Override
  public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    return new ScramSaslServer(protocol, serverName, props, cbh);
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[0];
  }
}
