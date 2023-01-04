/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

package io.mapsmessaging.sasl.provider.scram.server.state;

import io.mapsmessaging.sasl.provider.scram.State;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class ValidationState  extends State {

  private boolean isComplete;

  public ValidationState(State state){
    super(state);
    isComplete = false;
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
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    String proofString = response.remove(ChallengeResponse.PROOF);
    byte[] proof = Base64.getDecoder().decode(proofString);
    //
    // Compute Proof
    //
    String authString = context.getInitialClientChallenge()+","+context.getInitialServerChallenge()+","+response;
    try {
      context.computeClientKey(context.getPrepPassword().getBytes());
      context.computeStoredKeyAndSignature(authString);
      context.computeServerSignature(context.getPrepPassword().getBytes(), authString);
      byte[] signature = context.getClientSignature().clone();
      for (int i = 0; i < signature.length; i++) {
        signature[i] ^= proof[i];
      }
      if (!Arrays.equals(signature, context.getClientKey())) {
        throw new SaslException("Invalid password");
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      SaslException saslException = new SaslException(e.getMessage());
      saslException.initCause(e);
      throw saslException;
    }
  }
}