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

package io.mapsmessaging.security.sasl.provider;

import io.mapsmessaging.security.sasl.provider.plain.PlainSaslClient;
import io.mapsmessaging.security.sasl.provider.scram.client.ScramSaslClient;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

public class MapsSaslClientFactory implements SaslClientFactory {

  @Override
  public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
      throws SaslException {
    for (String mechanism : mechanisms) {
      String mech = mechanism.toLowerCase().trim();
      if (mech.startsWith("scram")) {
        String algorithm = mech.substring("scram-".length());
        return new ScramSaslClient(algorithm, authorizationId, protocol, serverName, props, cbh);
      }
      if (mech.startsWith("plain")) {
        return new PlainSaslClient(cbh);
      }
    }
    throw new SaslException("Unknown mechanism " + mechanisms);
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[]{"SCRAM"};
  }
}
