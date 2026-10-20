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
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

public class MapsSaslClientFactory implements SaslClientFactory {

  private static final String SCRAM_SHA_256 = "SCRAM-SHA-256";
  private static final String PLAIN = "PLAIN";

  @Override
  public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
      throws SaslException {
    if (mechanisms == null || cbh == null) {
      return null;
    }
    for (String mechanism : mechanisms) {
      if (SCRAM_SHA_256.equals(mechanism) && isScramAllowed(props)) {
        return new ScramSaslClient("SHA-256", authorizationId, protocol, serverName, props, cbh);
      }
      if (PLAIN.equals(mechanism) && isPlainAllowed(props)) {
        return new PlainSaslClient(authorizationId, cbh);
      }
    }
    return null;
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    if (isScramAllowed(props) && isPlainAllowed(props)) {
      return new String[] {SCRAM_SHA_256, PLAIN};
    }
    if (isScramAllowed(props)) {
      return new String[] {SCRAM_SHA_256};
    }
    if (isPlainAllowed(props)) {
      return new String[] {PLAIN};
    }
    return new String[0];
  }

  private boolean isPlainAllowed(Map<String, ?> props) {
    return supportsAuthQop(props)
        && !isRequired(props, Sasl.POLICY_NOPLAINTEXT)
        && !isRequired(props, Sasl.POLICY_NOACTIVE)
        && !isRequired(props, Sasl.POLICY_NODICTIONARY)
        && !isRequired(props, Sasl.POLICY_FORWARD_SECRECY)
        && !isRequired(props, Sasl.POLICY_PASS_CREDENTIALS);
  }

  private boolean isScramAllowed(Map<String, ?> props) {
    return supportsAuthQop(props)
        && !isRequired(props, Sasl.POLICY_NODICTIONARY)
        && !isRequired(props, Sasl.POLICY_FORWARD_SECRECY)
        && !isRequired(props, Sasl.POLICY_PASS_CREDENTIALS);
  }

  private boolean supportsAuthQop(Map<String, ?> props) {
    if (props == null || props.get(Sasl.QOP) == null) {
      return true;
    }
    for (String qop : String.valueOf(props.get(Sasl.QOP)).split(",")) {
      if ("auth".equals(qop.trim())) {
        return true;
      }
    }
    return false;
  }

  private boolean isRequired(Map<String, ?> props, String property) {
    return props != null && Boolean.parseBoolean(String.valueOf(props.get(property)));
  }
}
