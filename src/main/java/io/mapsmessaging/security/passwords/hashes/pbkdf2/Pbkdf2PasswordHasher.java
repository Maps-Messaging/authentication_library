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

package io.mapsmessaging.security.passwords.hashes.pbkdf2;

import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public abstract class Pbkdf2PasswordHasher extends PasswordHasher {

  private final byte[] salt;
  private final PasswordBuffer hash;
  private final int cost;

  protected Pbkdf2PasswordHasher(char[] password) {
    // Find the positions of the dollar signs
    int firstDollar = ArrayHelper.indexOf(password, '$');
    int secondDollar = ArrayHelper.indexOf(password, '$', firstDollar + 1);
    int thirdDollar = ArrayHelper.indexOf(password, '$', secondDollar + 1);

    if (firstDollar == -1 || secondDollar == -1 || thirdDollar == -1) {
      cost = getIterationCount();
      salt = PasswordGenerator.generateSaltBytes(getHashByteSize());
      hash = new PasswordBuffer(new char[0]);
    } else {
      // Extract cost
      char[] costChars = ArrayHelper.substring(password, firstDollar + 1, secondDollar);
      cost = ArrayHelper.parseInt(costChars);

      // Extract salt
      char[] saltChars = ArrayHelper.substring(password, secondDollar + 1, thirdDollar);
      byte[] saltBytes = ArrayHelper.charArrayToByteArray(saltChars);
      salt = Base64.getDecoder().decode(saltBytes);

      // Extract hash
      char[] hashChars = ArrayHelper.substring(password, thirdDollar + 1);
      byte[] hashBytes = ArrayHelper.charArrayToByteArray(hashChars);
      hash = new PasswordBuffer(ArrayHelper.byteArrayToCharArray(Base64.getDecoder().decode(hashBytes)));
      ArrayHelper.clearCharArray(saltChars);
      ArrayHelper.clearByteArray(saltBytes);
      ArrayHelper.clearCharArray(hashChars);
      ArrayHelper.clearByteArray(hashBytes);
    }
  }

  public abstract String getAlgorithm();

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

  @SuppressWarnings("java:S112") // Yes we know, if the JVM is not one we support then this will happen
  @Override
  public char[] transformPassword(char[] password, byte[] salt, int cost) {
    try {
      PBEKeySpec spec = new PBEKeySpec(password, salt, cost, getHashByteSize());
      SecretKeyFactory skf = SecretKeyFactory.getInstance(getAlgorithm());
      byte[] hash1 = skf.generateSecret(spec).getEncoded();
      return (
          getKey() +
              "$" +
              cost +
              "$" +
              Base64.getEncoder().encodeToString(salt) +
              "$" +
              Base64.getEncoder().encodeToString(hash1)
      ).toCharArray();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException("Error while hashing password", e);
    }
  }

  @Override
  public byte[] getSalt() {
    return salt;
  }

  @Override
  public PasswordBuffer getPassword() {
    return hash;
  }

  @Override
  public char[] getFullPasswordHash() {
    return ArrayHelper.appendCharArrays(
        getKey().toCharArray(),
        "$".toCharArray(),
        (""+cost).toCharArray(),
        "$".toCharArray(),
        Base64.getEncoder().encodeToString(salt).toCharArray(),
        "$".toCharArray(),
        Base64.getEncoder().encodeToString(hash.getBytes()).toCharArray()
    );
  }

  @Override
  public int getCost() {
    return cost;
  }
}
