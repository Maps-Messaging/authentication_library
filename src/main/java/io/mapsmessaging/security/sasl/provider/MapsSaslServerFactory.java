/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
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

package io.mapsmessaging.security.sasl.provider;

import io.mapsmessaging.security.sasl.provider.plain.PlainSaslServer;
import io.mapsmessaging.security.sasl.provider.scram.server.ScramSaslServer;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

public class MapsSaslServerFactory implements SaslServerFactory {

  @Override
  public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    String mech = mechanism.toLowerCase().trim();
    if (mech.startsWith("scram")) {
      String algorithm = mech.substring("scram-".length());
      return new ScramSaslServer(algorithm, protocol, serverName, props, cbh);
    }
    if (mech.startsWith("plain")) {
      return new PlainSaslServer(cbh);
    }
    throw new SaslException("Unknown mechanism " + mechanism);
  }

  @Override
  public String[] getMechanismNames(Map<String, ?> props) {
    return new String[]{"SCRAM"};
  }
}
