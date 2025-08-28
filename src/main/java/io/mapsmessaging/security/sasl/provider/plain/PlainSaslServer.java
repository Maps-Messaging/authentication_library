/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.security.auth.callback.*;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class PlainSaslServer implements SaslServer {

  private final CallbackHandler callbackHandler;
  private String authorizationId;
  private boolean complete;

  public PlainSaslServer(CallbackHandler cbh) {
    callbackHandler = cbh;
    complete = false;
  }

  @Override
  public String getMechanismName() {
    return "PLAIN";
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    if (response == null || response.length == 0) return new byte[0];
    authorizationId = new String(readTillNull(response, 1));
    byte[] password = readTillNull(response, authorizationId.length() + 2);

    //
    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("Username Prompt", authorizationId);
    callbacks[1] = new PasswordCallback("Password Prompt", false);
    try {
      callbackHandler.handle(callbacks);
    } catch (IOException | UnsupportedCallbackException e) {
      SaslException saslException = new SaslException();
      saslException.initCause(e);
      throw saslException;
    }
    String username = ((NameCallback) callbacks[0]).getName();
    if (username == null) {
      throw new SaslException("Invalid username or password");
    }

    String passwordHash = new String(((PasswordCallback) callbacks[1]).getPassword());
    String clientPassword = new String(password);
    if (!clientPassword.equals(passwordHash)) {
      throw new SaslException("Invalid username or password");
    }
    complete = true;
    return new byte[0];
  }

  private byte[] readTillNull(byte[] buffer, int offset) {
    ByteArrayOutputStream tmp = new ByteArrayOutputStream(1024);
    int x = offset;
    while (x < buffer.length && buffer[x] != 0) {
      tmp.write(buffer[x]);
      x++;
    }
    return tmp.toByteArray();
  }

  @Override
  public boolean isComplete() {
    return complete;
  }

  @Override
  public String getAuthorizationID() {
    return authorizationId;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    return new byte[0];
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    return new byte[0];
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return "auth-conf";
  }

  @Override
  public void dispose() throws SaslException {
    // We have nothing to dispose of here
  }
}
