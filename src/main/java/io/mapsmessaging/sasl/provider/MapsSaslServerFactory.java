package io.mapsmessaging.sasl.provider;

import io.mapsmessaging.sasl.provider.scram.server.ScramSaslServer;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

public class MapsSaslServerFactory implements SaslServerFactory {

  @Override
  public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    if(mechanism.toLowerCase().startsWith("scram")){
      return new ScramSaslServer(protocol, serverName, props, cbh);
    }
    throw new SaslException("Unknown mechanism "+mechanism);
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[]{"SCRAM"};
  }
}

