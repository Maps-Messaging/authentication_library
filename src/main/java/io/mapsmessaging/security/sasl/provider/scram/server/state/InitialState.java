/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.sasl.provider.scram.server.state;

import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.logging.AuthLogMessages;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.sasl.SaslPrep;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import javax.security.auth.callback.*;

public class InitialState extends State {

  public InitialState(String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
    super("", protocol, serverName, props, cbh);
    logger.log(AuthLogMessages.SCRAM_SERVER_STATE_CHANGE, "Initial State");
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  @Override
  public boolean hasInitialResponse() {
    return false;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) {
    if (!context.isReceivedClientMessage()) {
      return null;
    }
    String salt = new String(context.getPasswordSalt(), StandardCharsets.UTF_8);
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.NONCE, context.getServerNonce());
    response.put(ChallengeResponse.ITERATION_COUNT, String.valueOf(context.getIterations()));
    response.put(ChallengeResponse.SALT, salt);
    context.setState(new ValidationState(this));
    context.setInitialServerChallenge(response.toString());
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context)
      throws IOException, UnsupportedCallbackException {
    if (response.isEmpty()) {
      return;
    }
    context.setInitialClientChallenge(response.getOriginalRequest());

    //
    // Set up the context with the received information
    //
    context.setReceivedClientMessage(true);
    context.setUsername(response.get(ChallengeResponse.USERNAME));
    context.setClientNonce(response.get(ChallengeResponse.NONCE));

    //
    // Get the server back end user information
    //
    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("SCRAM Username Prompt", context.getUsername());
    callbacks[1] = new PasswordCallback("SCRAM Password Prompt", false);
    cbh.handle(callbacks);
    String username = ((NameCallback) callbacks[0]).getName();
    if (username == null) {
      throw new IOException("Require a username to be able to log in");
    }

    char[] password = ((PasswordCallback) callbacks[1]).getPassword();
    try {
      PasswordHandler handler = PasswordHandlerFactory.getInstance().parse(password);
      context.setPasswordHasher(handler);
      context.setPrepPassword(SaslPrep.getInstance().stringPrep(handler.getPassword().getHash()));
      byte[] salt = handler.getSalt();
      if (salt == null || salt.length == 0) {
        salt = PasswordGenerator.generateSalt(64).getBytes(StandardCharsets.UTF_8);
      }
      context.setPasswordSalt(Base64.getEncoder().encode(salt));
      int iterations = handler.getCost();
      if (iterations == 0) {
        iterations = 10_000;
      }
      context.setIterations(iterations);
      context.setServerNonce(context.getClientNonce() + CryptoHelper.generateNonce(48));
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    }
  }
}