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

package io.mapsmessaging.security.auth.parsers;

import io.mapsmessaging.security.auth.PasswordParser;

public class PlainPasswordParser implements PasswordParser {

  private final byte[] password;

  public PlainPasswordParser() {
    password = new byte[0];
  }

  public PlainPasswordParser(String password) {
    this.password = password.getBytes();
  }

  public PasswordParser create(String password) {
    return new PlainPasswordParser(password);
  }

  @Override
  public String getKey() {
    return "";
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    return new byte[0];
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public byte[] getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return new String(password).toCharArray();
  }

  @Override
  public String getName() {
    return "PLAIN";
  }
}
