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

package io.mapsmessaging.security.sasl.provider.scram.server.state;

import io.mapsmessaging.security.logging.AuthLogMessages;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

public class ValidationState extends State {

  private boolean complete;

  public ValidationState(State state) {
    super(state);
    logger.log(AuthLogMessages.SCRAM_SERVER_STATE_CHANGE, "Validating State");
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
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.VERIFIER, Base64.getEncoder().encodeToString(context.getServerSignature()));
    complete = true;
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context) throws IOException {
    List<String> keys = response.keys();
    if (keys.size() < 3 || !keys.subList(0, 2).equals(List.of(ChallengeResponse.CHANNEL_BINDING, ChallengeResponse.NONCE)) || !ChallengeResponse.PROOF.equals(keys.get(keys.size() - 1))) {
      throw new SaslException("Invalid SCRAM client-final message");
    }
    verifyChannelBinding(response, context);
    if (!context.getServerNonce().equals(response.get(ChallengeResponse.NONCE))) {
      throw new SaslException("Invalid SCRAM nonce");
    }

    String proofValue = response.remove(ChallengeResponse.PROOF);
    byte[] proof;
    try {
      proof = Base64.getDecoder().decode(proofValue);
    } catch (IllegalArgumentException e) {
      throw new SaslException("Invalid SCRAM client proof", e);
    }
    context.setClientFinalWithoutProof(response.getBareMessage());
    String authString = context.getInitialClientChallenge() + "," + context.getInitialServerChallenge() + "," + context.getClientFinalWithoutProof();

    byte[] expectedProof = null;
    try {
      context.computeClientKey(context.getPrepPassword());
      context.computeStoredKeyAndSignature(authString);
      expectedProof = context.getClientKey().clone();
      for (int i = 0; i < expectedProof.length; i++) {
        expectedProof[i] ^= context.getClientSignature()[i];
      }
      if (!context.isAuthenticationIdentityValid() || !MessageDigest.isEqual(expectedProof, proof)) {
        throw new SaslException("Invalid username or password");
      }
      try {
        authorize(context);
      } catch (UnsupportedCallbackException e) {
        throw new SaslException("SCRAM authorization callback is not supported", e);
      }
      context.computeServerSignature(context.getPrepPassword(), authString);
    } catch (GeneralSecurityException e) {
      throw new SaslException("Unable to validate SCRAM proof", e);
    } finally {
      Arrays.fill(proof, (byte) 0);
      if (expectedProof != null) {
        Arrays.fill(expectedProof, (byte) 0);
      }
    }
  }

  private void verifyChannelBinding(ChallengeResponse response, SessionContext context) throws SaslException {
    byte[] channelBinding;
    try {
      channelBinding = Base64.getDecoder().decode(response.get(ChallengeResponse.CHANNEL_BINDING));
    } catch (IllegalArgumentException e) {
      throw new SaslException("Invalid SCRAM channel binding", e);
    }
    if (!MessageDigest.isEqual(channelBinding, context.getGs2Header().getBytes(StandardCharsets.UTF_8))) {
      throw new SaslException("SCRAM channel binding does not match the GS2 header");
    }
  }

  private void authorize(SessionContext context) throws IOException, UnsupportedCallbackException {
    String requestedId = context.getAuthorizationId() == null ? context.getUsername() : context.getAuthorizationId();
    AuthorizeCallback authorizeCallback = new AuthorizeCallback(context.getUsername(), requestedId);
    cbh.handle(new Callback[] {authorizeCallback});
    if (!authorizeCallback.isAuthorized()) {
      throw new SaslException("SCRAM authorization identity is not permitted");
    }
    context.setAuthorizedId(authorizeCallback.getAuthorizedID() == null ? requestedId : authorizeCallback.getAuthorizedID());
  }
}
