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

package io.mapsmessaging.security.sasl.provider.scram.client;

import io.mapsmessaging.security.auth.parsers.bcrypt.BCrypt2yPasswordParser;
import io.mapsmessaging.security.sasl.provider.scram.BaseScramSasl;
import io.mapsmessaging.security.sasl.provider.scram.client.state.InitialState;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import javax.crypto.Mac;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

public class ScramSaslClient extends BaseScramSasl implements SaslClient {

  public ScramSaslClient(String algorithm, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws NoSuchAlgorithmException {
    if(algorithm.startsWith("bcrypt")){
      context.setPasswordParser(new BCrypt2yPasswordParser());
      algorithm = algorithm.substring("bcrypt-".length());
    }
    context.setMac(Mac.getInstance("Hmac"+algorithm.toUpperCase()));
    context.setState(new InitialState(authorizationId, protocol, serverName, props, cbh));
  }

  @Override
  public String getMechanismName() {
    return null;
  }

  @Override
  public boolean hasInitialResponse() {
    return context.getState().hasInitialResponse();
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if(propName.equals(Sasl.QOP)){
      return "auth";
    }
    return null;
  }
}
