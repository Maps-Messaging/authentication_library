/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.passwords.hashes.plain;

import io.mapsmessaging.security.passwords.PasswordHasher;

import java.nio.charset.StandardCharsets;

public class PlainPasswordHasher implements PasswordHasher {

  private final byte[] password;

  public PlainPasswordHasher() {
    password = new byte[0];
  }

  public PlainPasswordHasher(String password) {
    int ind = password.indexOf("$");
    if (ind != -1) {
      this.password = password.substring(ind + 1).getBytes(StandardCharsets.UTF_8);
    } else {
      this.password = password.getBytes(StandardCharsets.UTF_8);
    }
  }

  public PasswordHasher create(String password) {
    return new PlainPasswordHasher(password);
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
  public byte[] transformPassword(byte[] password, byte[] salt, int cost) {
    byte[] tmp = (getName() + "$").getBytes(StandardCharsets.UTF_8);
    byte[] response = new byte[tmp.length + password.length];
    System.arraycopy(tmp, 0, response, 0, tmp.length);
    System.arraycopy(password, 0, response, tmp.length, password.length);
    return response;
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
    return (getName() + "$" + new String(password)).toCharArray();
  }

  @Override
  public String getName() {
    return "PLAIN";
  }
}
