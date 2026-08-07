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
import io.mapsmessaging.security.passwords.PasswordCipher;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.hashes.plain.PlainPasswordHasher;
import io.mapsmessaging.security.sasl.SaslPrep;
import io.mapsmessaging.security.sasl.provider.scram.ScramString;
import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class InitialState extends State {

  private static final int MIN_ITERATIONS = 4096;
  private static final int DEFAULT_ITERATIONS = 10_000;
  private static final int MAX_ITERATIONS = 1_000_000;
  private static final String ITERATIONS_PROPERTY = "io.mapsmessaging.security.sasl.scram.iterations";

  public InitialState(String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
    super("", protocol, serverName, props, cbh);
    logger.log(AuthLogMessages.SCRAM_SERVER_STATE_CHANGE, "Initial State");
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
  public ChallengeResponse produceChallenge(SessionContext context) {
    if (!context.isReceivedClientMessage()) {
      return null;
    }
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.NONCE, context.getServerNonce());
    response.put(ChallengeResponse.SALT, Base64.getEncoder().encodeToString(context.getPasswordSalt()));
    response.put(ChallengeResponse.ITERATION_COUNT, String.valueOf(context.getIterations()));
    context.setInitialServerChallenge(response.getBareMessage());
    context.setState(new ValidationState(this));
    return response;
  }

  @Override
  public void handleResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    if (response.getGs2Header().isEmpty() || response.keys().size() < 2 || !response.keys().subList(0, 2).equals(List.of(ChallengeResponse.USERNAME, ChallengeResponse.NONCE))) {
      throw new SaslException("Invalid SCRAM client-first message");
    }

    String username = SaslPrep.getInstance().stringPrep(ScramString.unescapeSaslName(required(response, ChallengeResponse.USERNAME)));
    if (username.isEmpty()) {
      throw new SaslException("SCRAM username is empty after SASLprep");
    }
    String nonce = required(response, ChallengeResponse.NONCE);
    ScramString.requireNonce(nonce);
    context.setUsername(username);
    context.setClientNonce(nonce);
    context.setGs2Header(response.getGs2Header());
    context.setAuthorizationId(parseAuthorizationId(response.getGs2Header()));
    context.setInitialClientChallenge(response.getOriginalRequest().substring(response.getGs2Header().length()));
    context.setReceivedClientMessage(true);

    char[] password = readPassword(username, context);
    try {
      char[] preparedPassword = SaslPrep.getInstance().stringPrep(password);
      context.setPrepPassword(preparedPassword == password ? preparedPassword.clone() : preparedPassword);
    } finally {
      Arrays.fill(password, '\0');
    }
    context.setPasswordSalt(CryptoHelper.generateRandomBytes(16));
    context.setIterations(readIterations());
    context.setServerNonce(nonce + CryptoHelper.generateNonce(24));
  }

  private char[] readPassword(String username, SessionContext context) throws UnsupportedCallbackException {
    NameCallback nameCallback = new NameCallback("SCRAM username", username);
    PasswordCallback passwordCallback = new PasswordCallback("SCRAM password", false);
    char[] storedCopy = null;
    try {
      cbh.handle(new Callback[] {nameCallback, passwordCallback});
      char[] storedPassword = passwordCallback.getPassword();
      if (nameCallback.getName() == null || storedPassword == null) {
        throw new IOException("Unknown identity");
      }
      storedCopy = Arrays.copyOf(storedPassword, storedPassword.length);
      PasswordHandler handler = PasswordHandlerFactory.getInstance().parse(storedCopy);
      if (!(handler instanceof PlainPasswordHasher) && !(handler instanceof PasswordCipher)) {
        throw new IOException("SCRAM requires a reversible password or SCRAM verifier");
      }
      char[] decodedPassword = handler.getPassword().getHash();
      char[] result = Arrays.copyOf(decodedPassword, decodedPassword.length);
      Arrays.fill(decodedPassword, '\0');
      context.setAuthenticationIdentityValid(true);
      return result;
    } catch (IOException | GeneralSecurityException | RuntimeException e) {
      context.setAuthenticationIdentityValid(false);
      return CryptoHelper.generateNonce(24).toCharArray();
    } finally {
      passwordCallback.clearPassword();
      if (storedCopy != null) {
        Arrays.fill(storedCopy, '\0');
      }
    }
  }

  private String parseAuthorizationId(String gs2Header) throws SaslException {
    String value = gs2Header.substring(2, gs2Header.length() - 1);
    if (value.isEmpty()) {
      return null;
    }
    String authorizationId = SaslPrep.getInstance().stringPrep(ScramString.unescapeSaslName(value.substring(2)));
    if (authorizationId.isEmpty()) {
      throw new SaslException("SCRAM authorization identity is empty after SASLprep");
    }
    return authorizationId;
  }

  private int readIterations() throws SaslException {
    if (props == null || props.get(ITERATIONS_PROPERTY) == null) {
      return DEFAULT_ITERATIONS;
    }
    int value;
    try {
      value = Integer.parseInt(String.valueOf(props.get(ITERATIONS_PROPERTY)));
    } catch (NumberFormatException e) {
      throw new SaslException("Invalid SCRAM iteration count property", e);
    }
    if (value < MIN_ITERATIONS || value > MAX_ITERATIONS) {
      throw new SaslException("SCRAM iteration count is outside the permitted range");
    }
    return value;
  }

  private String required(ChallengeResponse response, String name) throws SaslException {
    String value = response.get(name);
    if (value == null || value.isEmpty()) {
      throw new SaslException("Missing SCRAM attribute: " + name);
    }
    return value;
  }
}
