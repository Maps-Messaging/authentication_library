/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class MapsSecurityProvider extends Provider {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final String CLIENT_FACTORY = "io.mapsmessaging.security.sasl.provider.MapsSaslClientFactory";
  private static final String SERVER_FACTORY = "io.mapsmessaging.security.sasl.provider.MapsSaslServerFactory";

  public MapsSecurityProvider() {
    super("MapsSasl", "1.0", "Provider for SCRAM SASL implementation.");
    Provider[] providers = Security.getProviders();
    for (Provider provider : providers) {
      for (Service service : provider.getServices()) {
        if (service.getAlgorithm().toLowerCase().startsWith("hmac")) {
          register(service.getAlgorithm().substring("hmac".length()));
        }
      }
    }
    if (Boolean.parseBoolean(System.getProperty("sasl.test", "false"))) {
      put("SaslClientFactory.MAPS-TEST-10", CLIENT_FACTORY);
      put("SaslServerFactory.MAPS-TEST-10", SERVER_FACTORY);
    }
    put("SaslClientFactory.PLAIN", CLIENT_FACTORY);
    put("SaslServerFactory.PLAIN", SERVER_FACTORY);
  }

  public static void register() {
    Provider[] providers = Security.getProviders();
    boolean found = false;
    for (Provider provider : providers) {
      if (provider instanceof MapsSecurityProvider) {
        found = true;
        break;
      }
    }
    if (!found) Security.insertProviderAt(new MapsSecurityProvider(), 1);
  }

  private void register(String hmacAlgorithm) {
    if (hmacAlgorithm.toLowerCase().startsWith("sha") && !hmacAlgorithm.toLowerCase().startsWith("sha3")) {
      hmacAlgorithm = hmacAlgorithm.substring(0, "sha".length()) + "-" + hmacAlgorithm.substring("sha".length());
    }
    put("SaslClientFactory.SCRAM-" + hmacAlgorithm, CLIENT_FACTORY);
    put("SaslServerFactory.SCRAM-" + hmacAlgorithm, SERVER_FACTORY);
    put("SaslClientFactory.SCRAM-bcrypt-" + hmacAlgorithm, CLIENT_FACTORY);
    put("SaslServerFactory.SCRAM-bcrypt-" + hmacAlgorithm, SERVER_FACTORY);
  }
}
