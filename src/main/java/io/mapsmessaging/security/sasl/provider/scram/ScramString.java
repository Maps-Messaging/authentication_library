/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

package io.mapsmessaging.security.sasl.provider.scram;

import javax.security.sasl.SaslException;

public final class ScramString {

  private ScramString() {}

  public static String escapeSaslName(String value) {
    return value.replace("=", "=3D").replace(",", "=2C");
  }

  public static String unescapeSaslName(String value) throws SaslException {
    StringBuilder result = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char current = value.charAt(i);
      if (current != '=') {
        result.append(current);
        continue;
      }
      if (i + 2 >= value.length()) {
        throw new SaslException("Invalid SCRAM saslname escape");
      }
      String escape = value.substring(i, i + 3);
      if ("=2C".equals(escape)) {
        result.append(',');
      } else if ("=3D".equals(escape)) {
        result.append('=');
      } else {
        throw new SaslException("Invalid SCRAM saslname escape");
      }
      i += 2;
    }
    return result.toString();
  }

  public static void requireNonce(String nonce) throws SaslException {
    if (nonce == null || nonce.isEmpty() || nonce.length() > 1024) {
      throw new SaslException("Invalid SCRAM nonce");
    }
    for (int i = 0; i < nonce.length(); i++) {
      char value = nonce.charAt(i);
      if (value == ',' || value < 0x21 || value > 0x7e) {
        throw new SaslException("Invalid SCRAM nonce");
      }
    }
  }
}
