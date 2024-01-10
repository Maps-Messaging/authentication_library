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

package io.mapsmessaging.security.identity.parsers.hmac;

import java.util.Base64;
import lombok.Data;

@Data
public class HmacData {
  private String algorithm;
  private byte[] salt;
  private String hmac;

  public HmacData(String password) {
    String[] parts = password.split(":");
    if (parts.length != 3) {
      throw new IllegalArgumentException("Invalid HMAC data string");
    }
    algorithm = parts[0];
    salt = Base64.getDecoder().decode(parts[1]);
    hmac = parts[2];
  }

  public String toString() {
    return algorithm + ":" + salt + ":" + hmac;
  }

  public boolean hasSalt() {
    return salt != null && salt.length > 0;
  }
}
