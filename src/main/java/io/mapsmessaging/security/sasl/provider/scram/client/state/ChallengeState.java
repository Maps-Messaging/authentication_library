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

import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.NONCE, context.getServerNonce());
    response.put(ChallengeResponse.CHANNEL_BINDING, "biws");

    String saltedPassword = "";
    if (context.getPasswordHasher() != null) {
      byte[] salt =
          Base64.getDecoder().decode(context.getPasswordSalt().getBytes(StandardCharsets.UTF_8));
      byte[] computedHash =
          context
              .getPasswordHasher()
              .transformPassword(
                  context.getPrepPassword().getBytes(StandardCharsets.UTF_8),
                  salt,
                  context.getIterations());
      PasswordHandler breakDown = context.getPasswordHasher().create(new String(computedHash));
      saltedPassword = new String(breakDown.getPassword());
    }

    //
    // Compute Proof
    //
    try {
      String authString = context.getInitialClientChallenge() + "," + context.getInitialServerChallenge() + "," + response;
      context.computeClientHashes(saltedPassword.getBytes(), authString);
      response.put(ChallengeResponse.PROOF, Base64.getEncoder().encodeToString(context.getClientProof()));

      //
      // Compute the expected server response
      //
      context.computeServerSignature(saltedPassword.getBytes(), authString);

    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      SaslException saslException = new SaslException(e.getMessage());
      saslException.initCause(e);
      throw saslException;
    }

    context.setPrepPassword(saltedPassword);
    context.setState(new FinalValidationState(this));
    return response;
  }

  @Override
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    context.setInitialServerChallenge(response.toString());
    context.setServerNonce(response.get(ChallengeResponse.NONCE));
    context.setPasswordSalt(response.get(ChallengeResponse.SALT));
    context.setIterations(Integer.parseInt(response.get(ChallengeResponse.ITERATION_COUNT)));
  }
}
