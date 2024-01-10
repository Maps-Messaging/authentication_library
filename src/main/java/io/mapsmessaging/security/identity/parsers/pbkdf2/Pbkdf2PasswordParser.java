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

package io.mapsmessaging.security.identity.parsers.pbkdf2;

import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public abstract class Pbkdf2PasswordParser implements PasswordParser {

  private final byte[] salt;
  private final byte[] hash;

  private final int cost;

  public Pbkdf2PasswordParser(String password) {
    String[] split = password.split("\\$");
    if (split.length == 4) {
      // split[0] can be ignored since it was used to construc this class
      cost = Integer.parseInt(split[1]);
      salt = Base64.getDecoder().decode(split[2]);
      hash = Base64.getDecoder().decode(split[3]);
    } else {
      cost = getIterationCount();
      salt = PasswordGenerator.generateSaltBytes(getHashByteSize());
      hash = null;
    }
  }

  protected abstract String getAlgorithm();

  protected abstract int getIterationCount();

  protected abstract int getHashByteSize();

  @Override
  public String getKey() {
    return getName();
  }

  @Override
  public boolean hasSalt() {
    return true;
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    try {
      PBEKeySpec spec =
          new PBEKeySpec(new String(password).toCharArray(), salt, cost, getHashByteSize());
      SecretKeyFactory skf = SecretKeyFactory.getInstance(getAlgorithm());
      byte[] hash = skf.generateSecret(spec).getEncoded();
      return (getKey()
              + "$"
              + cost
              + "$"
              + Base64.getEncoder().encodeToString(salt)
              + "$"
              + Base64.getEncoder().encodeToString(hash))
          .getBytes();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Error while hashing password", e);
    }
  }

  @Override
  public byte[] getSalt() {
    return salt;
  }

  @Override
  public byte[] getPassword() {
    return hash;
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getKey()
            + "$"
            + cost
            + "$"
            + Base64.getEncoder().encodeToString(salt)
            + "$"
            + Base64.getEncoder().encodeToString(hash))
        .toCharArray();
  }

  @Override
  public int getCost() {
    return cost;
  }
}
