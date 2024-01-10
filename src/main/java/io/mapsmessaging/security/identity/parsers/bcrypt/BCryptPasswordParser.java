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

package io.mapsmessaging.security.identity.parsers.bcrypt;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import at.favre.lib.crypto.bcrypt.Radix64Encoder;
import io.mapsmessaging.security.identity.parsers.PasswordParser;

import java.nio.charset.StandardCharsets;

public abstract class BCryptPasswordParser implements PasswordParser {

  private final Version version;
  private final byte[] password;
  private final byte[] salt;
  private final int cost;

  protected BCryptPasswordParser() {
    password = new byte[0];
    salt = new byte[0];
    cost = 12;
    version = null;
  }

  protected BCryptPasswordParser(Version version) {
    password = new byte[0];
    salt = new byte[0];
    cost = 12;
    this.version = version;
  }

  protected BCryptPasswordParser(String password, Version version) {
    this.version = version;
    if (password.isEmpty()) {
      salt = new byte[0];
      this.password = new byte[0];
      cost = 12;
    } else {
      String t = password.substring(getKey().length());
      int dollar = t.indexOf("$");
      cost = Integer.parseInt(t.substring(0, dollar));
      t = t.substring(dollar + 1);
      String s = t.substring(0, 22);
      String p = t.substring(23);
      Radix64Encoder encoder = new Radix64Encoder.Default();
      salt = encoder.decode(s.getBytes(StandardCharsets.UTF_8));
      this.password = encoder.decode(p.getBytes(StandardCharsets.UTF_8));
    }
  }

  @Override
  public int getCost() {
    return cost;
  }

  @Override
  public boolean hasSalt() {
    return true;
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    return BCrypt.with(version).hash(cost, salt, password);
  }

  @Override
  public byte[] getSalt() {
    return salt;
  }

  @Override
  public byte[] getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    Radix64Encoder encoder = new Radix64Encoder.Default();
    String t = new String(encoder.encode(salt)) + new String(encoder.encode(password));
    return (getKey() + cost + "$" + t).toCharArray();
  }

  @Override
  public String getName() {
    return "BCrypt";
  }
}
