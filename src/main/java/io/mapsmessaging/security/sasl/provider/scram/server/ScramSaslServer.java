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

package io.mapsmessaging.security.sasl.provider.scram.server;

import io.mapsmessaging.security.logging.AuthLogMessages;
import io.mapsmessaging.security.sasl.provider.scram.BaseScramSasl;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import io.mapsmessaging.security.sasl.provider.scram.server.state.InitialState;
import java.util.Map;
import javax.crypto.Mac;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class ScramSaslServer extends BaseScramSasl implements SaslServer {

  public ScramSaslServer(String algorithm, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    Mac mac = CryptoHelper.findMac(algorithm);
    if (mac != null) {
      context.setMac(mac);
    } else {
      throw new SaslException("Unable to compute MAC algiorithm");
    }

    logger.log(AuthLogMessages.SCRAM_SERVER_INITIAL_PHASE, algorithm);
    context.setState(new InitialState(protocol, serverName, props, cbh));
  }

  @Override
  public String getMechanismName() {
    return "SCRAM";
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    return super.evaluateChallenge(response);
  }

  @Override
  public String getAuthorizationID() {
    return context.getUsername();
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return "auth-conf";
  }

}
