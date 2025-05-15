/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.passwords.hashes.md5;

import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import org.apache.commons.codec.digest.Md5Crypt;

public class Md5PasswordHasher extends PasswordHasher {

  protected final PasswordBuffer password;
  protected final byte[] salt;

  public Md5PasswordHasher() {
    password = new PasswordBuffer(new char[0]);
    salt = new byte[0];
  }

  protected Md5PasswordHasher(char[] password) {
    if (password == null || password.length == 0) {
      this.password = new PasswordBuffer(new char[0]);
      this.salt = new byte[0];
    } else {
      char[] sub = ArrayHelper.substring(password, getKey().length());
      int split = ArrayHelper.indexOf(sub, '$');

      char[] pw = new char[0];
      char[] sl = new char[0];

      if (split != -1) {
        sl = ArrayHelper.substring(sub, 0, split);
        pw = ArrayHelper.substring(sub, split + 1);
      }

      this.password = new PasswordBuffer(pw);
      this.salt = ArrayHelper.charArrayToByteArray(sl);

      // Clear temporary arrays to avoid sensitive data lingering in memory
      ArrayHelper.clearCharArray(sub);
      ArrayHelper.clearCharArray(sl);
    }
  }

  public PasswordHasher create(char[] password) {
    return new Md5PasswordHasher(password);
  }

  @Override
  public String getKey() {
    return "$apr1$";
  }

  @Override
  public boolean hasSalt() {
    return salt.length > 0;
  }

  @Override
  public char[] transformPassword(char[] password, byte[] salt, int cost) {
    return Md5Crypt.apr1Crypt(ArrayHelper.charArrayToByteArray(password), new String(salt)).toCharArray();
  }

  @Override
  public byte[] getSalt() {
    return salt;
  }

  @Override
  public PasswordBuffer getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return ArrayHelper.appendCharArrays(getKey().toCharArray(), ArrayHelper.byteArrayToCharArray(salt), "$".toCharArray(), password.getHash());
  }

  @Override
  public String getName() {
    return "MD5";
  }
}
