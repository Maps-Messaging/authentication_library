/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

public abstract class ShaPasswordParser implements PasswordParser {

  private final byte[] password;
  private final String salt;
  private final String key;

  protected ShaPasswordParser(String key, String password) {
    this.key = key;
    int idx = password.indexOf("$");
    if(idx > 0){
      salt = password.substring(0, idx);
      password = password.substring(idx+1);
      this.password = password.getBytes();
    }
    else{
      this.password = new byte[0];
      salt = "";
    }
  }

  @Override
  public String getKey() {
    return key;
  }

  @Override
  public boolean hasSalt() {
    return salt == null || salt.length() == 0;
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    return Crypt.crypt(password, new String(salt)).getBytes();
  }

  @Override
  public byte[] getSalt() {
    return (key+salt).getBytes();
  }

  @Override
  public byte[] getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getKey() + new String(password)).toCharArray();
  }


}