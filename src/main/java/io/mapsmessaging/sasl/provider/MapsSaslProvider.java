package io.mapsmessaging.sasl.provider;

import java.security.Provider;

public class MapsSaslProvider extends Provider {

  private static final String CLIENT_FACTORY = "io.mapsmessaging.sasl.provider.MapsSaslClientFactory";
  private static final String SERVER_FACTORY = "io.mapsmessaging.sasl.provider.MapsSaslServerFactory";


  public MapsSaslProvider() {
    super("MapsSasl", "1.0", "Provider for SCRAM SASL implementation.");
    put("SaslClientFactory.SCRAM", CLIENT_FACTORY);
    put("SaslServerFactory.SCRAM", SERVER_FACTORY);
  }

}
