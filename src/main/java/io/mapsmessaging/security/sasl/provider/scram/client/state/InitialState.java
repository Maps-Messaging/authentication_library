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

package io.mapsmessaging.security.sasl.provider.scram.client.state;

import io.mapsmessaging.security.sasl.SaslPrep;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.*;

public class InitialState extends State {

  private static final String GS2_HEADER = "n,,";

  public InitialState(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
    super(authorizationId, protocol, serverName, props, cbh);
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  public boolean hasInitialResponse() {
    return false;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    context.setClientNonce(CryptoHelper.generateNonce(48));
    ChallengeResponse firstClientChallenge = new ChallengeResponse();
    //
    // Request information from the user
    //
    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("SCRAM Username Prompt");
    callbacks[1] = new PasswordCallback("SCRAM Password Prompt", false);
    cbh.handle(callbacks);

    //
    // Update the context
    //
    String rawPassword = new String((((PasswordCallback) callbacks[1]).getPassword()));

    context.setUsername(((NameCallback) callbacks[0]).getName());
    context.setPrepPassword(SaslPrep.getInstance().stringPrep(rawPassword));

    //
    // Set up the initial challenge
    //
    firstClientChallenge.put(ChallengeResponse.USERNAME, context.getUsername());
    firstClientChallenge.put(ChallengeResponse.NONCE, context.getClientNonce());
    context.setState(new ChallengeState(this));
    context.setInitialClientChallenge(firstClientChallenge.getOriginalRequest());
    firstClientChallenge.setGs2Header(GS2_HEADER);
    return firstClientChallenge;
  }

  @Override
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    // This is the first state, there is no challenge or response
  }
}
