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

import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class ChallengeState extends State {

  public ChallengeState(State state) {
    super(state);
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
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException {
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.NONCE, context.getServerNonce());
    response.put(ChallengeResponse.CHANNEL_BINDING, "biws");

    byte[] saltedPassword=new byte[0];
    try {
      if (context.getPasswordHasher() != null) {
        byte[] salt = Base64.getDecoder().decode(context.getPasswordSalt());
        char[] computedHash = context.getPasswordHasher().transformPassword(context.getPrepPassword(), salt, context.getIterations());
        PasswordHandler breakDown = context.getPasswordHasher().create(computedHash);
        saltedPassword = breakDown.getPassword().getBytes();
      }

    //
    // Compute Proof
    //
      String authString = context.getInitialClientChallenge() + "," + context.getInitialServerChallenge() + "," + response;
      context.computeClientHashes(saltedPassword, authString);
      response.put(ChallengeResponse.PROOF, Base64.getEncoder().encodeToString(context.getClientProof()));

      //
      // Compute the expected server response
      //
      context.computeServerSignature(saltedPassword, authString);

    } catch (GeneralSecurityException e) {
      SaslException saslException = new SaslException(e.getMessage());
      saslException.initCause(e);
      throw saslException;
    }
    context.setState(new FinalValidationState(this));
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context)
      throws IOException, UnsupportedCallbackException {
    context.setInitialServerChallenge(response.toString());
    context.setServerNonce(response.get(ChallengeResponse.NONCE));
    context.setPasswordSalt(response.get(ChallengeResponse.SALT).getBytes(StandardCharsets.UTF_8));
    context.setIterations(Integer.parseInt(response.get(ChallengeResponse.ITERATION_COUNT)));
  }
}
