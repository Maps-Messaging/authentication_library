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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class ChallengeState extends State {

  private static final int MIN_ITERATIONS = 4096;
  private static final int DEFAULT_MAX_ITERATIONS = 1_000_000;
  private static final String MAX_ITERATIONS_PROPERTY = "io.mapsmessaging.security.sasl.scram.maxIterations";

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
    response.put(ChallengeResponse.CHANNEL_BINDING, Base64.getEncoder().encodeToString(context.getGs2Header().getBytes(StandardCharsets.UTF_8)));
    response.put(ChallengeResponse.NONCE, context.getServerNonce());
    context.setClientFinalWithoutProof(response.getBareMessage());

    String authString = context.getInitialClientChallenge() + "," + context.getInitialServerChallenge() + "," + context.getClientFinalWithoutProof();
    try {
      context.computeClientHashes(context.getPrepPassword(), authString);
      context.computeServerSignature(context.getPrepPassword(), authString);
    } catch (GeneralSecurityException e) {
      throw new SaslException("Unable to calculate SCRAM proof", e);
    }
    response.put(ChallengeResponse.PROOF, Base64.getEncoder().encodeToString(context.getClientProof()));
    context.setState(new FinalValidationState(this));
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    List<String> expectedAttributes = List.of(ChallengeResponse.NONCE, ChallengeResponse.SALT, ChallengeResponse.ITERATION_COUNT);
    if (!response.getGs2Header().isEmpty() || !response.keys().subList(0, Math.min(3, response.keys().size())).equals(expectedAttributes)) {
      throw new SaslException("Invalid SCRAM server-first message");
    }
    String nonce = required(response, ChallengeResponse.NONCE);
    context.setServerNonce(nonce);

    byte[] salt;
    try {
      salt = Base64.getDecoder().decode(required(response, ChallengeResponse.SALT));
    } catch (IllegalArgumentException e) {
      throw new SaslException("Invalid SCRAM salt", e);
    }
    if (salt.length < 8 || salt.length > 1024) {
      throw new SaslException("Invalid SCRAM salt length");
    }

    int iterations;
    try {
      iterations = Integer.parseInt(required(response, ChallengeResponse.ITERATION_COUNT));
    } catch (NumberFormatException e) {
      throw new SaslException("Invalid SCRAM iteration count", e);
    }
    int maxIterations = propertyAsInt(MAX_ITERATIONS_PROPERTY, DEFAULT_MAX_ITERATIONS);
    if (iterations < MIN_ITERATIONS || iterations > maxIterations) {
      throw new SaslException("SCRAM iteration count is outside the permitted range");
    }
    context.setPasswordSalt(salt);
    context.setIterations(iterations);
    context.setInitialServerChallenge(response.getOriginalRequest());
  }

  private String required(ChallengeResponse response, String name) throws SaslException {
    String value = response.get(name);
    if (value == null || value.isEmpty()) {
      throw new SaslException("Missing SCRAM attribute: " + name);
    }
    return value;
  }

  private int propertyAsInt(String name, int defaultValue) throws SaslException {
    if (props == null || props.get(name) == null) {
      return defaultValue;
    }
    try {
      return Integer.parseInt(String.valueOf(props.get(name)));
    } catch (NumberFormatException e) {
      throw new SaslException("Invalid SCRAM property: " + name, e);
    }
  }
}
