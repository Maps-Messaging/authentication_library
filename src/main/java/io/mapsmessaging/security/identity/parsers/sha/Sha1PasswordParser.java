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
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class Sha1PasswordParser implements PasswordParser {

  private final byte[] password;

  public Sha1PasswordParser() {
    password = new byte[0];
  }

  protected Sha1PasswordParser(String password) {
    this.password = password.getBytes();
  }

  public PasswordParser create(String password) {
    return new Sha1PasswordParser(password);
  }

  @Override
  public String getKey() {
    return "{SHA}";
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @SuppressWarnings("java:S4790") // this is weak but used to test
  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    return (getKey() + Base64.encodeBase64String(DigestUtils.sha1(password))).getBytes();
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
    return (getKey() + new String(password)).toCharArray();
  }

  @Override
  public String getName() {
    return "SHA1";
  }
}