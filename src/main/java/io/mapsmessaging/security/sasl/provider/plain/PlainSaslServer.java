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

package io.mapsmessaging.security.sasl.provider.plain;

import io.mapsmessaging.security.passwords.PasswordCipher;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class PlainSaslServer implements SaslServer {

  private static final int MAX_RESPONSE_SIZE = 16 * 1024;

  private final CallbackHandler callbackHandler;
  private String authorizationId;
  private boolean complete;
  private boolean disposed;

  public PlainSaslServer(CallbackHandler callbackHandler) {
    this.callbackHandler = callbackHandler;
  }

  @Override
  public String getMechanismName() {
    return "PLAIN";
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    if (disposed || complete) {
      throw new SaslException("PLAIN authentication is not active");
    }
    if (response == null || response.length == 0 || response.length > MAX_RESPONSE_SIZE) {
      throw new SaslException("Invalid PLAIN response size");
    }
    int firstNull = indexOfNull(response, 0);
    int secondNull = firstNull < 0 ? -1 : indexOfNull(response, firstNull + 1);
    if (firstNull < 0 || secondNull < 0 || secondNull == firstNull + 1 || secondNull == response.length - 1 || indexOfNull(response, secondNull + 1) >= 0) {
      throw new SaslException("Invalid PLAIN response");
    }

    String requestedAuthorizationId = decodeString(response, 0, firstNull);
    String authenticationId = decodeString(response, firstNull + 1, secondNull);
    char[] suppliedPassword = decodeCharacters(response, secondNull + 1, response.length);
    try {
      validatePassword(authenticationId, suppliedPassword);
      authorizationId = authorize(authenticationId, requestedAuthorizationId.isEmpty() ? authenticationId : requestedAuthorizationId);
      complete = true;
      return null;
    } finally {
      Arrays.fill(suppliedPassword, '\0');
    }
  }

  private void validatePassword(String authenticationId, char[] suppliedPassword) throws SaslException {
    NameCallback nameCallback = new NameCallback("PLAIN username", authenticationId);
    PasswordCallback passwordCallback = new PasswordCallback("PLAIN password", false);
    char[] expected = null;
    char[] candidate = null;
    char[] storedCopy = null;
    try {
      callbackHandler.handle(new Callback[] {nameCallback, passwordCallback});
      char[] storedPassword = passwordCallback.getPassword();
      if (nameCallback.getName() == null || storedPassword == null) {
        throw new SaslException("Invalid username or password");
      }
      storedCopy = Arrays.copyOf(storedPassword, storedPassword.length);
      PasswordHandler handler = PasswordHandlerFactory.getInstance().parse(storedCopy);
      if (handler instanceof PasswordCipher) {
        expected = handler.getPassword().getHash();
        candidate = Arrays.copyOf(suppliedPassword, suppliedPassword.length);
      } else {
        expected = handler.getFullPasswordHash();
        candidate = handler.transformPassword(suppliedPassword, handler.getSalt(), handler.getCost());
      }
      byte[] encodedCandidate = encode(candidate);
      byte[] encodedExpected = encode(expected);
      try {
        if (!MessageDigest.isEqual(encodedCandidate, encodedExpected)) {
          throw new SaslException("Invalid username or password");
        }
      } finally {
        Arrays.fill(encodedCandidate, (byte) 0);
        Arrays.fill(encodedExpected, (byte) 0);
      }
    } catch (IOException | UnsupportedCallbackException | GeneralSecurityException | RuntimeException e) {
      throw new SaslException("Invalid username or password", e);
    } finally {
      passwordCallback.clearPassword();
      clear(storedCopy);
      clear(expected);
      clear(candidate);
    }
  }

  private String authorize(String authenticationId, String requestedAuthorizationId) throws SaslException {
    AuthorizeCallback authorizeCallback = new AuthorizeCallback(authenticationId, requestedAuthorizationId);
    try {
      callbackHandler.handle(new Callback[] {authorizeCallback});
    } catch (IOException | UnsupportedCallbackException e) {
      throw new SaslException("Unable to authorize PLAIN identity", e);
    }
    if (!authorizeCallback.isAuthorized()) {
      throw new SaslException("PLAIN authorization identity is not permitted");
    }
    return authorizeCallback.getAuthorizedID() == null ? requestedAuthorizationId : authorizeCallback.getAuthorizedID();
  }

  @Override
  public boolean isComplete() {
    return complete && !disposed;
  }

  @Override
  public String getAuthorizationID() {
    requireComplete();
    return authorizationId;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    throw new IllegalStateException("PLAIN does not negotiate a security layer");
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    throw new IllegalStateException("PLAIN does not negotiate a security layer");
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    requireComplete();
    return Sasl.QOP.equals(propName) ? "auth" : null;
  }

  @Override
  public void dispose() throws SaslException {
    authorizationId = null;
    complete = false;
    disposed = true;
  }

  private void requireComplete() {
    if (!isComplete()) {
      throw new IllegalStateException("PLAIN authentication is not complete");
    }
  }

  private int indexOfNull(byte[] value, int offset) {
    for (int i = offset; i < value.length; i++) {
      if (value[i] == 0) {
        return i;
      }
    }
    return -1;
  }

  private String decodeString(byte[] value, int start, int end) throws SaslException {
    return new String(decodeCharacters(value, start, end));
  }

  private char[] decodeCharacters(byte[] value, int start, int end) throws SaslException {
    try {
      CharBuffer decoded =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(value, start, end - start));
      char[] result = new char[decoded.remaining()];
      decoded.get(result);
      return result;
    } catch (CharacterCodingException e) {
      throw new SaslException("PLAIN response is not valid UTF-8", e);
    }
  }

  private byte[] encode(char[] value) {
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(value));
    byte[] result = new byte[encoded.remaining()];
    encoded.get(result);
    return result;
  }

  private void clear(char[] value) {
    if (value != null) {
      Arrays.fill(value, '\0');
    }
  }
}
