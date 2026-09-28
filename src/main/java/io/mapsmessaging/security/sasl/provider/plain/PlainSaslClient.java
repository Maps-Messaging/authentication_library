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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class PlainSaslClient implements SaslClient {

  private static final int MAX_RESPONSE_SIZE = 16 * 1024;

  private final String authorizationId;
  private final CallbackHandler callbackHandler;
  private boolean complete;
  private boolean disposed;

  public PlainSaslClient(CallbackHandler callbackHandler) {
    this(null, callbackHandler);
  }

  public PlainSaslClient(String authorizationId, CallbackHandler callbackHandler) {
    this.authorizationId = authorizationId == null ? "" : authorizationId;
    this.callbackHandler = callbackHandler;
  }

  @Override
  public String getMechanismName() {
    return "PLAIN";
  }

  @Override
  public boolean hasInitialResponse() {
    return true;
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    if (disposed || complete) {
      throw new SaslException("PLAIN authentication is not active");
    }
    if (challenge != null && challenge.length != 0) {
      throw new SaslException("PLAIN does not accept a server challenge");
    }
    NameCallback nameCallback = new NameCallback("PLAIN username");
    PasswordCallback passwordCallback = new PasswordCallback("PLAIN password", false);
    try {
      callbackHandler.handle(new Callback[] {nameCallback, passwordCallback});
      String username = nameCallback.getName();
      char[] password = passwordCallback.getPassword();
      if (username == null || username.isEmpty() || password == null || password.length == 0) {
        throw new SaslException("PLAIN credentials are required");
      }
      requireNoNull(authorizationId);
      requireNoNull(username);
      requireNoNull(password);

      byte[] authzid = encode(authorizationId);
      byte[] authcid = encode(username);
      byte[] passwordBytes = encode(password);
      if ((long) authzid.length + authcid.length + passwordBytes.length + 2 > MAX_RESPONSE_SIZE) {
        Arrays.fill(passwordBytes, (byte) 0);
        throw new SaslException("PLAIN response exceeds the maximum size");
      }
      byte[] response = new byte[authzid.length + authcid.length + passwordBytes.length + 2];
      System.arraycopy(authzid, 0, response, 0, authzid.length);
      System.arraycopy(authcid, 0, response, authzid.length + 1, authcid.length);
      System.arraycopy(passwordBytes, 0, response, authzid.length + authcid.length + 2, passwordBytes.length);
      Arrays.fill(passwordBytes, (byte) 0);
      complete = true;
      return response;
    } catch (IOException | UnsupportedCallbackException e) {
      throw new SaslException("Unable to obtain PLAIN credentials", e);
    } finally {
      passwordCallback.clearPassword();
    }
  }

  @Override
  public boolean isComplete() {
    return complete && !disposed;
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
    disposed = true;
    complete = false;
  }

  private void requireComplete() {
    if (!isComplete()) {
      throw new IllegalStateException("PLAIN authentication is not complete");
    }
  }

  private void requireNoNull(String value) throws SaslException {
    if (value.indexOf('\0') >= 0) {
      throw new SaslException("PLAIN identity contains a NUL character");
    }
  }

  private void requireNoNull(char[] value) throws SaslException {
    for (char character : value) {
      if (character == '\0') {
        throw new SaslException("PLAIN password contains a NUL character");
      }
    }
  }

  private byte[] encode(String value) throws SaslException {
    return encode(CharBuffer.wrap(value));
  }

  private byte[] encode(char[] value) throws SaslException {
    return encode(CharBuffer.wrap(value));
  }

  private byte[] encode(CharBuffer value) throws SaslException {
    try {
      ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(value);
      byte[] result = new byte[encoded.remaining()];
      encoded.get(result);
      return result;
    } catch (CharacterCodingException e) {
      throw new SaslException("PLAIN credentials are not valid UTF-8", e);
    }
  }
}
