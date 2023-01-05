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

package io.mapsmessaging.security.sasl.provider.scram.server;

import io.mapsmessaging.security.identity.parsers.bcrypt.BCrypt2yPasswordParser;
import io.mapsmessaging.security.sasl.provider.scram.BaseScramSasl;
import io.mapsmessaging.security.sasl.provider.scram.server.state.InitialState;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import javax.crypto.Mac;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class ScramSaslServer extends BaseScramSasl implements SaslServer {

  public ScramSaslServer(String algorithm, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    if (algorithm.startsWith("bcrypt")) {
      context.setPasswordParser(new BCrypt2yPasswordParser());
      algorithm = algorithm.substring("bcrypt-".length());
    }
    try {
      context.setMac(Mac.getInstance("Hmac" + algorithm.toUpperCase()));
    } catch (NoSuchAlgorithmException e) {
      SaslException saslException = new SaslException(e.getMessage());
      saslException.initCause(e);
      throw saslException;
    }
    context.setState(new InitialState(protocol, serverName, props, cbh));
  }

  @Override
  public String getMechanismName() {
    return null;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    return super.evaluateChallenge(response);
  }

  @Override
  public String getAuthorizationID() {
    return null;
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return null;
  }

}
