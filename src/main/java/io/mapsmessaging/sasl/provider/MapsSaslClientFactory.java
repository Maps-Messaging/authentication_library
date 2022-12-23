package io.mapsmessaging.sasl.provider;

import io.mapsmessaging.sasl.provider.scram.client.ScramSaslClient;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

public class MapsSaslClientFactory implements SaslClientFactory {

  @Override
  public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
      throws SaslException {
    for(String mechanism:mechanisms){
      if(mechanism.toLowerCase().startsWith("scram")){
        return new ScramSaslClient(authorizationId, protocol, serverName, props, cbh);
      }
    }
    throw new SaslException("Unknown mechanism "+mechanisms);
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[]{"SCRAM"};
  }
}
