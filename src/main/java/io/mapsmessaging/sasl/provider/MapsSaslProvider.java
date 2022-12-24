/*
 * Copyright [ 2020 - 2022 ] [Matthew Buckton]
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

package io.mapsmessaging.sasl.provider;

import java.security.Provider;

public class MapsSaslProvider extends Provider {

  private static final String CLIENT_FACTORY = "io.mapsmessaging.sasl.provider.MapsSaslClientFactory";
  private static final String SERVER_FACTORY = "io.mapsmessaging.sasl.provider.MapsSaslServerFactory";


  public MapsSaslProvider() {
    super("MapsSasl", "1.0", "Provider for SCRAM SASL implementation.");
    put("SaslClientFactory.SCRAM", CLIENT_FACTORY);
    put("SaslServerFactory.SCRAM", SERVER_FACTORY);
  }

}
