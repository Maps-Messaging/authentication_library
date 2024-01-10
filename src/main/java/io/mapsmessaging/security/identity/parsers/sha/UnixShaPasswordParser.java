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

package io.mapsmessaging.security.identity.parsers.sha;

import io.mapsmessaging.security.identity.parsers.PasswordParser;
import org.apache.commons.codec.digest.Crypt;

import java.nio.charset.StandardCharsets;

public abstract class UnixShaPasswordParser implements PasswordParser {

  private final byte[] password;
  private final String salt;
  private final String key;

  protected UnixShaPasswordParser(String key, String password) {
    this.key = key;
    if (password.isEmpty()) {
      salt = "";
      this.password = new byte[0];
    } else {
      password = password.substring(key.length());
      int idx = password.indexOf("$");
      if (idx > 0) {
        salt = password.substring(0, idx);
        password = password.substring(idx + 1);
        this.password = password.getBytes(StandardCharsets.UTF_8);
      } else {
        this.password = new byte[0];
        salt = "";
      }
    }
  }

  @Override
  public String getKey() {
    return key;
  }

  @Override
  public boolean hasSalt() {
    return salt == null || salt.isEmpty();
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    boolean headerOk = true;
    byte[] packedSalt = salt;
    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
    for (int x = 0; x < keyBytes.length; x++) {
      if (salt[x] != keyBytes[x]) {
        headerOk = false;
        break;
      }
    }
    if (!headerOk) {
      packedSalt = (key + new String(salt)).getBytes(StandardCharsets.UTF_8);
    }
    String hash = Crypt.crypt(password, new String(packedSalt));
    return hash.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public byte[] getSalt() {
    return salt.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public byte[] getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return (key + salt + "$" + new String(password)).toCharArray();
  }

  @Override
  public int getCost() {
    return 5000;
  }
}