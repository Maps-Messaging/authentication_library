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

package io.mapsmessaging.security.sasl.provider.scram.server.state;

import io.mapsmessaging.security.logging.AuthLogMessages;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class ValidationState extends State {

  private boolean isComplete;

  public ValidationState(State state) {
    super(state);
    isComplete = false;
    logger.log(AuthLogMessages.SCRAM_SERVER_STATE_CHANGE, "Validating State");
  }


  @Override
  public boolean hasInitialResponse() {
    return true;
  }

  @Override
  public boolean isComplete() {
    return isComplete;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.VERIFIER, Base64.getEncoder().encodeToString(context.getServerSignature()));
    isComplete = true;
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context)
      throws IOException, UnsupportedCallbackException {
    String proofString = response.remove(ChallengeResponse.PROOF);
    byte[] proof = Base64.getDecoder().decode(proofString);
    String client = context.getInitialClientChallenge();
    if (client.startsWith("n,,")) client = client.substring(3);
    String authString = client + "," + context.getInitialServerChallenge() + "," + response;

    try {
      context.computeClientKey(context.getPrepPassword().getBytes(StandardCharsets.UTF_8));
      context.computeStoredKeyAndSignature(authString);

      byte[] clientKey = context.getClientKey();
      byte[] clientSignature = context.getClientSignature();
      byte[] expectedClientProof = new byte[clientSignature.length];
      for (int i = 0; i < clientSignature.length; i++) {
        expectedClientProof[i] = (byte) (clientKey[i] ^ clientSignature[i]);
      }
      if (!Arrays.equals(expectedClientProof, proof)) {
        throw new SaslException("Invalid password");
      }

      context.computeServerSignature(
          context.getPrepPassword().getBytes(StandardCharsets.UTF_8), authString);
      context.setServerSignature(context.getServerSignature());
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      SaslException saslException = new SaslException(e.getMessage());
      saslException.initCause(e);
      throw saslException;
    } catch (InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }
}