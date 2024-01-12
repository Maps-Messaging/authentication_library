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

package io.mapsmessaging.security.identity.parsers.hmac.sha;

import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.hmac.HmacData;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public abstract class ShaHmacProcessor implements PasswordParser {

  private final HmacData hmacData;

  protected ShaHmacProcessor(HmacData data) {
    hmacData = data;
  }

  @Override
  public String getKey() {
    return hmacData.getHmac();
  }

  @Override
  public boolean hasSalt() {
    return hmacData.hasSalt();
  }

  public byte[] transformPassword(byte[] password, byte[] salt, int cost) {
    try {
      MessageDigest digest = MessageDigest.getInstance(getName());
      digest.reset();
      digest.update(salt);
      byte[] encodedhash = digest.digest(password);

      for (int i = 0; i < cost - 1; i++) {
        encodedhash = digest.digest(encodedhash);
      }
      return Base64.getEncoder().encode(encodedhash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] getSalt() {
    return hmacData.getSalt();
  }

  @Override
  public byte[] getPassword() {
    return hmacData.getHmac().getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public char[] getFullPasswordHash() {
    return hmacData.toString().toCharArray();
  }

  @Override
  public int getCost() {
    return 5000;
  }
}
