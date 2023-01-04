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

package io.mapsmessaging.sasl.provider.scram.client.state;

import io.mapsmessaging.sasl.provider.scram.State;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class FinalValidationState extends State {

  private boolean isComplete;

  public FinalValidationState(State state){
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
    return null;
  }

  @Override
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    byte[] verifier = Base64.getDecoder().decode(response.get(ChallengeResponse.VERIFIER).getBytes());
    if (!Arrays.equals(verifier, context.getServerSignature())) {
      throw new SaslException("Invalid server signature received");
    }
    isComplete = true;
  }
}