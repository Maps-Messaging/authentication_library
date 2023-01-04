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

package io.mapsmessaging.security.sasl.impl.htpasswd.hash;

import org.apache.commons.codec.digest.Md5Crypt;

public class MD5PasswordHash implements PasswordHash {

  @Override
  public char[] hash(String password, String salt) {
    return Md5Crypt.apr1Crypt(password.getBytes(), salt ).toCharArray();
  }
}
