package io.mapsmessaging.sasl.provider;

import java.security.Provider;

public class MapsSaslProvider extends Provider {

  public MapsSaslProvider() {
    super("MapsSasl", "1.0", "Provider for SCRAM SASL implementation.");
    put("SaslClientFactory.SCRAM", "io.mapsmessaging.sasl.provider.scram.ScramSaslClientFactory");
    put("SaslServerFactory.SCRAM", "io.mapsmessaging.sasl.provider.scram.ScramSaslServerFactory");
  }

}
