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

package io.mapsmessaging.security.sasl;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.identity.IdentityLookup;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.security.sasl.Sasl;
import org.junit.jupiter.api.Assertions;

public class SaslTester extends BaseSasl {

  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "anyProtocol";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth";

  public void testMechanism(
      IdentityLookup identityLookup, String mechanism, String user, char[] password)
      throws IOException {
    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);
    createServer(identityLookup, mechanism, PROTOCOL, SERVER_NAME, props);
    createClient(user, password, new String[] {mechanism}, PROTOCOL, AUTHORIZATION_ID, SERVER_NAME, props);
    simpleValidation(user, mechanism);
  }

  void simpleValidation(String user, String mechanism) throws IOException {
    assertNotNull(saslServer, "This should not be null");
    assertNotNull(saslClient, "This should not be null");
    runAuth();
    assertTrue(saslServer.isComplete());
    assertTrue(saslClient.isComplete());

    String qop = (String) saslClient.getNegotiatedProperty(Sasl.QOP);
    Assertions.assertEquals(saslServer.getAuthorizationID(), user);
    Assertions.assertEquals("auth", qop);
    Assertions.assertEquals(mechanism, saslServer.getMechanismName());
    Assertions.assertEquals(mechanism, saslClient.getMechanismName());
    Assertions.assertThrows(IllegalStateException.class, () -> saslClient.wrap(new byte[1], 0, 1));
    Assertions.assertThrows(IllegalStateException.class, () -> saslServer.wrap(new byte[1], 0, 1));
    saslServer.dispose();
    saslClient.dispose();
  }
}
