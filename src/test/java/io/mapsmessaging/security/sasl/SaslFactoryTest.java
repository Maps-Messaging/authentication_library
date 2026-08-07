/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

package io.mapsmessaging.security.sasl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.mapsmessaging.security.MapsSecurityProvider;
import io.mapsmessaging.security.sasl.provider.MapsSaslClientFactory;
import io.mapsmessaging.security.sasl.provider.MapsSaslServerFactory;
import java.util.Map;
import javax.security.sasl.Sasl;
import org.junit.jupiter.api.Test;

class SaslFactoryTest {

  @Test
  void advertisesOnlyExplicitlySupportedMechanisms() throws Exception {
    MapsSaslClientFactory clientFactory = new MapsSaslClientFactory();
    MapsSaslServerFactory serverFactory = new MapsSaslServerFactory();
    assertArrayEquals(new String[] {"SCRAM-SHA-256", "PLAIN"}, clientFactory.getMechanismNames(Map.of()));
    assertArrayEquals(new String[] {"SCRAM-SHA-256", "PLAIN"}, serverFactory.getMechanismNames(Map.of()));
    assertArrayEquals(new String[] {"SCRAM-SHA-256"}, clientFactory.getMechanismNames(Map.of(Sasl.POLICY_NOPLAINTEXT, "true")));
    assertArrayEquals(new String[0], clientFactory.getMechanismNames(Map.of(Sasl.POLICY_NODICTIONARY, "true")));
    assertArrayEquals(new String[0], serverFactory.getMechanismNames(Map.of(Sasl.QOP, "auth-conf")));

    assertNull(clientFactory.createSaslClient(new String[] {"SCRAM-SHA-512"}, null, "test", "localhost", Map.of(), callbacks -> {}));
    assertNull(serverFactory.createSaslServer("SCRAM-SHA-1", "test", "localhost", Map.of(), callbacks -> {}));
    assertNull(clientFactory.createSaslClient(new String[] {"SCRAM-SHA-256"}, null, "test", "localhost", Map.of(Sasl.QOP, "auth-int"), callbacks -> {}));
  }

  @Test
  void providerDoesNotRegisterDiscoveredOrLegacyAlgorithms() {
    MapsSecurityProvider provider = new MapsSecurityProvider();
    assertNull(provider.getService("SaslClientFactory", "SCRAM-SHA-1"));
    assertNull(provider.getService("SaslClientFactory", "SCRAM-SHA-512"));
    assertNull(provider.getService("SaslClientFactory", "SCRAM-SHA3-512"));
  }
}
