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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.sasl.provider.plain.PlainSaslClient;
import io.mapsmessaging.security.sasl.provider.plain.PlainSaslServer;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class PlainSaslTest {

  @Test
  void supportsRfc4616AuthorizationIdentityAndUtf8() throws Exception {
    String authenticationId = "matthew-✓";
    String authorizationId = "service-✓";
    char[] password = "pässword-✓".toCharArray();
    PlainSaslClient client = new PlainSaslClient(authorizationId, callbacks -> setClientCredentials(callbacks, authenticationId, password));
    PlainSaslServer server = new PlainSaslServer(callbacks -> handleServerCallbacks(callbacks, authenticationId, authorizationId, password));

    byte[] response = client.evaluateChallenge(new byte[0]);
    server.evaluateResponse(response);

    assertTrue(client.isComplete());
    assertTrue(server.isComplete());
    assertEquals(authorizationId, server.getAuthorizationID());
  }

  @Test
  void rejectsMalformedResponse() {
    PlainSaslServer server = new PlainSaslServer(callbacks -> {});
    assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[] {0, 'u', 0, 'p', 0, 'x'}));
    assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[] {0, 0, 'p'}));
  }

  @Test
  void clientRejectsAChallengeBecausePlainIsClientFirst() {
    PlainSaslClient client = new PlainSaslClient(callbacks -> {});
    assertThrows(SaslException.class, () -> client.evaluateChallenge(new byte[] {'x'}));
  }

  private void setClientCredentials(Callback[] callbacks, String username, char[] password) {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback nameCallback) {
        nameCallback.setName(username);
      } else if (callback instanceof PasswordCallback passwordCallback) {
        passwordCallback.setPassword(password);
      }
    }
  }

  private void handleServerCallbacks(Callback[] callbacks, String authenticationId, String authorizationId, char[] password) {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback nameCallback) {
        if (authenticationId.equals(nameCallback.getDefaultName())) {
          nameCallback.setName(authenticationId);
        }
      } else if (callback instanceof PasswordCallback passwordCallback) {
        passwordCallback.setPassword(password);
      } else if (callback instanceof AuthorizeCallback authorizeCallback) {
        boolean authorized = authenticationId.equals(authorizeCallback.getAuthenticationID()) && authorizationId.equals(authorizeCallback.getAuthorizationID());
        authorizeCallback.setAuthorized(authorized);
        if (authorized) {
          authorizeCallback.setAuthorizedID(authorizationId);
        }
      }
    }
  }
}
