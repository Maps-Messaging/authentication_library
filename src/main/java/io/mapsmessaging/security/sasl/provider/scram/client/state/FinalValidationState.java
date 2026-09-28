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

import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class FinalValidationState extends State {

  private boolean complete;

  public FinalValidationState(State state) {
    super(state);
  }

  @Override
  public boolean hasInitialResponse() {
    return true;
  }

  @Override
  public boolean isComplete() {
    return complete;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    return null;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    if (response.contains(ChallengeResponse.SERVER_ERROR)) {
      throw new SaslException("SCRAM server rejected authentication: " + response.get(ChallengeResponse.SERVER_ERROR));
    }
    if (!response.keys().equals(List.of(ChallengeResponse.VERIFIER))) {
      throw new SaslException("Invalid SCRAM server-final message");
    }
    byte[] verifier;
    try {
      verifier = Base64.getDecoder().decode(response.get(ChallengeResponse.VERIFIER));
    } catch (IllegalArgumentException e) {
      throw new SaslException("Invalid SCRAM server verifier", e);
    }
    if (!MessageDigest.isEqual(verifier, context.getServerSignature())) {
      throw new SaslException("Invalid SCRAM server signature");
    }
    complete = true;
  }
}
