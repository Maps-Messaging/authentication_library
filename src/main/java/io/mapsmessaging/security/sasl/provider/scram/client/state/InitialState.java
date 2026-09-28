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

package io.mapsmessaging.security.sasl.provider.scram.client.state;

import io.mapsmessaging.security.sasl.SaslPrep;
import io.mapsmessaging.security.sasl.provider.scram.ScramString;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class InitialState extends State {

  public InitialState(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
    super(authorizationId, protocol, serverName, props, cbh);
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  @Override
  public boolean hasInitialResponse() {
    return true;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    NameCallback nameCallback = new NameCallback("SCRAM username");
    PasswordCallback passwordCallback = new PasswordCallback("SCRAM password", false);
    cbh.handle(new Callback[] {nameCallback, passwordCallback});

    String username = nameCallback.getName();
    char[] password = passwordCallback.getPassword();
    if (username == null || username.isEmpty() || password == null) {
      passwordCallback.clearPassword();
      throw new SaslException("SCRAM credentials are required");
    }

    String preparedUsername;
    try {
      preparedUsername = SaslPrep.getInstance().stringPrep(username);
      if (preparedUsername.isEmpty()) {
        throw new SaslException("SCRAM username is empty after SASLprep");
      }
      context.setUsername(preparedUsername);
      char[] preparedPassword = SaslPrep.getInstance().stringPrep(password);
      context.setPrepPassword(preparedPassword == password ? preparedPassword.clone() : preparedPassword);
    } finally {
      passwordCallback.clearPassword();
    }

    String preparedAuthorizationId = authorizationId == null || authorizationId.isEmpty() ? null : SaslPrep.getInstance().stringPrep(authorizationId);
    if (preparedAuthorizationId != null && preparedAuthorizationId.isEmpty()) {
      throw new SaslException("SCRAM authorization identity is empty after SASLprep");
    }
    context.setAuthorizationId(preparedAuthorizationId);
    String gs2Header = preparedAuthorizationId == null ? "n,," : "n,a=" + ScramString.escapeSaslName(preparedAuthorizationId) + ",";
    context.setGs2Header(gs2Header);

    context.setClientNonce(CryptoHelper.generateNonce(24));
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.USERNAME, ScramString.escapeSaslName(preparedUsername));
    response.put(ChallengeResponse.NONCE, context.getClientNonce());
    context.setInitialClientChallenge(response.getBareMessage());
    response.setGs2Header(gs2Header);
    context.setState(new ChallengeState(this));
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    throw new SaslException("SCRAM client received an unexpected initial challenge");
  }
}
