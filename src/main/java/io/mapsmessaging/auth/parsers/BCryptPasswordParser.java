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

package io.mapsmessaging.auth.parsers;

import at.favre.lib.crypto.bcrypt.Radix64Encoder;
import io.mapsmessaging.auth.PasswordParser;

public abstract class BCryptPasswordParser implements PasswordParser {

  private final String password;
  private final String salt;
  private final int cost;

  public BCryptPasswordParser(){
    password = "";
    salt = "";
    cost =0;
  }

  protected BCryptPasswordParser(String password){
    String t = password.substring(getKey().length());
    int dollar = t.indexOf("$");
    cost = Integer.parseInt(t.substring(0, dollar));
    t = t.substring(dollar+1);
    String s = t.substring(0, 22);
    String p = t.substring(23);
    salt = s;
    this.password = p;
  }

  @Override
  public boolean hasSalt() {
    return true;
  }

  @Override
  public char[] getSalt() {
    return salt.toCharArray();
  }

  public byte[] getRawSalt(){
    Radix64Encoder encoder = new  Radix64Encoder.Default();
    return encoder.decode(salt.getBytes());
  }

  @Override
  public char[] getPassword() {
    return password.toCharArray();
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getKey() + cost+"$"+salt+password).toCharArray();
  }

  @Override
  public String getName() {
    return "BCrypt";
  }
}
