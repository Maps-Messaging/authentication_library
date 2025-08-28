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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.security.auth.callback.*;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class PlainSaslClient implements SaslClient {

  private final CallbackHandler callbackHandler;
  private boolean complete;

  public PlainSaslClient(CallbackHandler cbh) {
    callbackHandler = cbh;
    complete = false;
  }

  @Override
  public String getMechanismName() {
    return "PLAIN";
  }

  @Override
  public boolean hasInitialResponse() {
    return false;
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("Username Prompt");
    callbacks[1] = new PasswordCallback("Password Prompt", false);
    try {
      callbackHandler.handle(callbacks);
    } catch (IOException | UnsupportedCallbackException e) {
      SaslException saslException = new SaslException();
      saslException.initCause(e);
      throw saslException;
    }
    String username = ((NameCallback) callbacks[0]).getName();
    String password = new String(((PasswordCallback) callbacks[1]).getPassword());
    byte[] user = username.getBytes(StandardCharsets.UTF_8);
    byte[] pass = password.getBytes(StandardCharsets.UTF_8);
    byte[] response = new byte[user.length + pass.length + 2];
    System.arraycopy(user, 0, response, 1, user.length);
    System.arraycopy(pass, 0, response, user.length + 2, pass.length);
    complete = true;
    return response;
  }

  @Override
  public boolean isComplete() {
    return complete;
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
    if (propName.equals(Sasl.QOP)) {
      return "auth";
    }
    return null;
  }

  @Override
  public void dispose() throws SaslException {
    // not required
  }
}
