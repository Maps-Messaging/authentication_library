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

package io.mapsmessaging.security.passwords.hashes.sha;

import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.commons.codec.digest.Crypt;

public abstract class UnixShaPasswordHasher extends PasswordHasher {

  private final PasswordBuffer password;
  private final String salt;
  private final char[] key;

  protected UnixShaPasswordHasher(char[] key, char[] pw) {
    this.key = key;
    if (pw.length == 0) {
      salt = "";
      password = new PasswordBuffer(new char[0]);
    } else {
      char[] subPassword = ArrayHelper.substring(pw, key.length);
      int idx = ArrayHelper.indexOf(subPassword, '$');
      if (idx > 0) {
        char[] saltChars = ArrayHelper.substring(subPassword, 0, idx);
        char[] remainingPassword = ArrayHelper.substring(subPassword, idx + 1);
        salt = new String(saltChars);
        password = new PasswordBuffer(Arrays.copyOf(remainingPassword, remainingPassword.length));

        // Clear sensitive data
        ArrayHelper.clearCharArray(saltChars);
        ArrayHelper.clearCharArray(remainingPassword);
      } else {
        password = new PasswordBuffer(new char[0]);
        salt = "";
      }

      // Clear sensitive data
      ArrayHelper.clearCharArray(subPassword);
    }
  }

  @Override
  public String getKey() {
    return new String(key);
  }

  @Override
  public boolean hasSalt() {
    return salt != null && !salt.isEmpty();
  }

  @Override
  public char[] transformPassword(char[] password, byte[] salt, int cost) {
    boolean headerOk = true;
    byte[] packedSalt = salt;
    byte[] keyBytes = ArrayHelper.charArrayToByteArray(key);
    for (int x = 0; x < keyBytes.length; x++) {
      if (salt[x] != keyBytes[x]) {
        headerOk = false;
        break;
      }
    }
    if (!headerOk) {
      packedSalt = (getKey() + new String(salt)).getBytes(StandardCharsets.UTF_8);
    }
    String hash = Crypt.crypt(ArrayHelper.charArrayToByteArray(password), new String(packedSalt));
    return hash.toCharArray();
  }

  @Override
  public byte[] getSalt() {
    return salt.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public PasswordBuffer getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return ArrayHelper.appendCharArrays(getKey().toCharArray(), salt.toCharArray(), "$".toCharArray(), password.getHash());
  }

  @Override
  public int getCost() {
    return 5000;
  }
}