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

package io.mapsmessaging.security.passwords.hashes.md5;

import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import org.apache.commons.codec.digest.Md5Crypt;

public class Md5UnixPasswordHasher extends Md5PasswordHasher {

  public Md5UnixPasswordHasher() {
    super();
  }

  protected Md5UnixPasswordHasher(char[] password) {
    super(password);
  }

  @Override
  public char[] transformPassword(char[] password, byte[] salt, int cost) {
    return Md5Crypt.md5Crypt(ArrayHelper.charArrayToByteArray(password), getKey() + new String(salt)).toCharArray();
  }

  @Override
  public String getKey() {
    return "$1$";
  }

  @Override
  public PasswordHasher create(char[] password) {
    return new Md5UnixPasswordHasher(password);
  }

  @Override
  public String getName() {
    return "MD5-Unix";
  }

}
