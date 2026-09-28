/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
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
    put("SaslClientFactory.SCRAM-SHA-256", CLIENT_FACTORY);
    put("SaslServerFactory.SCRAM-SHA-256", SERVER_FACTORY);
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

}
