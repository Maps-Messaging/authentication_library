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

import static com.ongres.scram.common.stringprep.StringPreparations.NO_PREPARATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ongres.scram.client.ScramClient;
import com.ongres.scram.client.ScramClient.ChannelBinding;
import com.ongres.scram.client.ScramSession;
import io.mapsmessaging.security.sasl.provider.scram.server.ScramSaslServer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslServer;
import org.junit.jupiter.api.Test;

class InterOperationTest {

  @Test
  void ongresClientAuthenticatesAgainstMapsServer() throws Exception {
    String username = "user";
    String password = "pencil";
    ScramClient scramClient =
        ScramClient.channelBinding(ChannelBinding.NO)
            .stringPreparation(NO_PREPARATION)
            .selectMechanismBasedOnServerAdvertised("SCRAM-SHA-256")
            .nonceSupplier(() -> "rOprNGfwEbeRWgbNEkqO")
            .setup();
    ScramSession session = scramClient.scramSession(username);
    SaslServer server = new ScramSaslServer("SHA-256", "test", "localhost", Map.of(), callbackHandler(username, password));

    byte[] serverFirst = server.evaluateResponse(session.clientFirstMessage().getBytes(StandardCharsets.UTF_8));
    ScramSession.ServerFirstProcessor serverFirstProcessor = session.receiveServerFirstMessage(new String(serverFirst, StandardCharsets.UTF_8));
    ScramSession.ClientFinalProcessor clientFinalProcessor = serverFirstProcessor.clientFinalProcessor(password);
    byte[] serverFinal = server.evaluateResponse(clientFinalProcessor.clientFinalMessage().getBytes(StandardCharsets.UTF_8));
    clientFinalProcessor.receiveServerFinalMessage(new String(serverFinal, StandardCharsets.UTF_8));

    assertTrue(server.isComplete());
    assertEquals(username, server.getAuthorizationID());
  }

  private CallbackHandler callbackHandler(String expectedUsername, String password) {
    return callbacks -> {
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback nameCallback) {
          if (expectedUsername.equals(nameCallback.getDefaultName())) {
            nameCallback.setName(expectedUsername);
          }
        } else if (callback instanceof PasswordCallback passwordCallback) {
          passwordCallback.setPassword(password.toCharArray());
        } else if (callback instanceof AuthorizeCallback authorizeCallback) {
          boolean authorized = authorizeCallback.getAuthenticationID().equals(authorizeCallback.getAuthorizationID());
          authorizeCallback.setAuthorized(authorized);
          if (authorized) {
            authorizeCallback.setAuthorizedID(authorizeCallback.getAuthorizationID());
          }
        }
      }
    };
  }
}
