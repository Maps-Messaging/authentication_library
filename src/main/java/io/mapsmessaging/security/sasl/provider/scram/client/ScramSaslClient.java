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

package io.mapsmessaging.security.sasl.provider.scram.client;

import io.mapsmessaging.security.sasl.provider.scram.BaseScramSasl;
import io.mapsmessaging.security.sasl.provider.scram.client.state.InitialState;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

public class ScramSaslClient extends BaseScramSasl implements SaslClient {

  private final String mechanismName;

  public ScramSaslClient(String algorithm, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
    mechanismName = "SCRAM-" + algorithm.toUpperCase();
    try {
      context.setMac(CryptoHelper.findMac(algorithm));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Unsupported SCRAM algorithm: " + algorithm, e);
    }
    context.setState(new InitialState(authorizationId, protocol, serverName, props, cbh));
  }

  @Override
  public String getMechanismName() {
    return mechanismName;
  }

  @Override
  public boolean hasInitialResponse() {
    return context.getState().hasInitialResponse();
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    requireComplete();
    if (propName.equals(Sasl.QOP)) {
      return "auth";
    }
    return null;
  }
}
