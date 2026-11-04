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

import io.mapsmessaging.security.MapsSecurityProvider;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

/** In-process SCRAM demonstration. Replace the local credentials and byte-array handoff in an application. */
public final class SaslExample {

  private static final String USERNAME = "alice";

  private SaslExample() {
  }

  public static void main(String[] arguments) throws IOException {
    MapsSecurityProvider.register();
    // Demo credentials only: a real client and server obtain these independently from their credential stores.
    char[] clientPassword = "example-password".toCharArray();
    char[] serverPassword = "example-password".toCharArray();
    Map<String, String> properties = Map.of(Sasl.QOP, "auth", Sasl.POLICY_NOPLAINTEXT, "true");
    SaslClient client = null;
    SaslServer server = null;
    try {
      client = Sasl.createSaslClient(new String[] {"SCRAM-SHA-256"}, USERNAME, "example", "localhost", properties,
          clientCallbacks(clientPassword));
      server = Sasl.createSaslServer("SCRAM-SHA-256", "example", "localhost", properties, serverCallbacks(serverPassword));
      if (client == null || server == null) {
        throw new SaslException("No SASL implementation satisfies the requested mechanism and policy");
      }

      // These handoffs replace the application's protocol framing and transport.
      byte[] clientFirst = client.evaluateChallenge(new byte[0]);
      byte[] serverFirst = server.evaluateResponse(clientFirst);
      byte[] clientFinal = client.evaluateChallenge(serverFirst);
      byte[] serverFinal = server.evaluateResponse(clientFinal);
      // The server is complete now, but the client must still validate the server's signature.
      byte[] finalResponse = client.evaluateChallenge(serverFinal);
      if (!server.isComplete() || !client.isComplete() || finalResponse != null) {
        throw new SaslException("SCRAM did not complete as expected");
      }
      if (!USERNAME.equals(server.getAuthorizationID())) {
        throw new SaslException("Unexpected authorized identity");
      }
      if (!"auth".equals(client.getNegotiatedProperty(Sasl.QOP)) || !"auth".equals(server.getNegotiatedProperty(Sasl.QOP))) {
        throw new SaslException("Unexpected negotiated QOP");
      }
      System.out.println("Authenticated and authorized: " + server.getAuthorizationID() + "; QOP=auth");
    } finally {
      // Attempt both disposals, including when peer creation or the exchange fails.
      try {
        if (client != null) {
          client.dispose();
        }
      } finally {
        try {
          if (server != null) {
            server.dispose();
          }
        } finally {
          Arrays.fill(clientPassword, '\0');
          Arrays.fill(serverPassword, '\0');
        }
      }
    }
  }

  private static CallbackHandler clientCallbacks(char[] password) {
    return (Callback[] callbacks) -> {
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback nameCallback) {
          nameCallback.setName(USERNAME);
        } else if (callback instanceof PasswordCallback passwordCallback) {
          passwordCallback.setPassword(password);
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
    };
  }

  private static CallbackHandler serverCallbacks(char[] storedPassword) {
    return (Callback[] callbacks) -> {
      // Resolve the name before supplying its credential, regardless of callback order.
      String requestedIdentity = null;
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback nameCallback) {
          requestedIdentity = nameCallback.getDefaultName();
        }
      }
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback nameCallback) {
          nameCallback.setName(USERNAME.equals(requestedIdentity) ? requestedIdentity : null);
        } else if (callback instanceof PasswordCallback passwordCallback) {
          if (!USERNAME.equals(requestedIdentity)) {
            throw new IOException("Unknown identity");
          }
          // SCRAM needs the recoverable password here, not a bcrypt/Argon2/PBKDF2 hash.
          passwordCallback.setPassword(storedPassword);
        } else if (callback instanceof AuthorizeCallback authorizeCallback) {
          boolean authorized = USERNAME.equals(authorizeCallback.getAuthenticationID())
              && authorizeCallback.getAuthenticationID().equals(authorizeCallback.getAuthorizationID());
          authorizeCallback.setAuthorized(authorized);
          if (authorized) {
            authorizeCallback.setAuthorizedID(authorizeCallback.getAuthorizationID());
          }
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
    };
  }
}
