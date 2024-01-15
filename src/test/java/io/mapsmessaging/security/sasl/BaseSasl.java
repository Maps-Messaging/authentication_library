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

package io.mapsmessaging.security.sasl;

import io.mapsmessaging.security.MapsSecurityProvider;
import io.mapsmessaging.security.identity.IdentityLookup;
import java.security.Security;
import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;

@SuppressWarnings("java:S2187") // Ignore the no test rule

public class BaseSasl {

  @BeforeAll
  static void register() {
    System.setProperty("sasl.test", "true");
    Security.insertProviderAt(new MapsSecurityProvider(), 1);
  }

  protected SaslServer saslServer;
  protected SaslClient saslClient;

  protected void createClient(String username,
      String password,
      String[] mechanism,
      String protocol,
      String authorizationId,
      String serverName,
      Map<String, String> props) throws SaslException {
    ClientCallbackHandler clientHandler = new ClientCallbackHandler(username, password, serverName);
    saslClient = Sasl.createSaslClient(mechanism, authorizationId, protocol, serverName, props, clientHandler);
  }

  protected void createServer(IdentityLookup identityLookup, String mechanism, String protocol, String serverName, Map<String, String> props) throws SaslException {
    saslServer =  Sasl.createSaslServer(mechanism, protocol, serverName, props, new ServerCallbackHandler(serverName, identityLookup));
  }

  protected void runAuth() throws SaslException {
    byte[] challenge;
    byte[] response = new byte[0];

    while (!saslClient.isComplete() && !saslServer.isComplete()) {
      if (response.length > 0) {
        System.err.println("Client>" + new String(response));
      }
      challenge = saslServer.evaluateResponse(response);
      if (challenge != null && challenge.length > 0) {
        System.err.println("Server>" + new String(challenge));
      }
      response = saslClient.evaluateChallenge(challenge);
    }
    if (response != null) {
      if (response.length > 0) {
        System.err.println("Client>" + new String(response));
      }
      saslServer.evaluateResponse(response);
    }
    System.err.println(
        "---------------------------------------------------------------------------------------------");
  }

  @AfterEach
  public void tearDown() throws SaslException {
    if(saslClient != null) saslClient.dispose();
    if(saslServer != null) saslServer.dispose();
  }


}
