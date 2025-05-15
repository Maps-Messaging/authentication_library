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

package io.mapsmessaging.security.passwords.hashes.plain;

import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import java.util.Arrays;

public class PlainPasswordHasher extends PasswordHasher {

  private final PasswordBuffer password;

  public PlainPasswordHasher() {
    password = new PasswordBuffer(new char[0]);
  }

  public PlainPasswordHasher(char[] pw) {
    int ind = ArrayHelper.indexOf(pw, '$', 1);
    if (ind != -1) {
      pw = ArrayHelper.substring(pw, ind + 1);
    }
    password = new PasswordBuffer(Arrays.copyOf(pw, pw.length));
    // Clear the original password array to avoid lingering sensitive data
    ArrayHelper.clearCharArray(pw);
  }

  public PasswordHasher create(char[] password) {
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
  public char[] transformPassword(char[] password, byte[] salt, int cost) {
    char[] tmp = (getName() + "$").toCharArray();
    char[] response = new char[tmp.length + password.length];
    System.arraycopy(tmp, 0, response, 0, tmp.length);
    System.arraycopy(password, 0, response, tmp.length, password.length);
    return response;
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public PasswordBuffer getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return ArrayHelper.appendCharArrays(getName().toCharArray(), "$".toCharArray(), password.getHash());
  }

  @Override
  public String getName() {
    return "PLAIN";
  }

  @Override
  public boolean matches(char[] attemptedPassword) {
    return Arrays.equals(attemptedPassword, getPassword().getHash());
  }
}
