/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.sasl.provider.scram.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;

public class CryptoHelper {

  private CryptoHelper() {
    // This is a helper class and does not have any instance methods
  }

  public static String generateNonce(int size) {
    byte[] nonce = generateRandomBytes(size);
    return Base64.getEncoder().encodeToString(nonce);
  }

  public static byte[] generateRandomBytes(int size) {
    byte[] value = new byte[size];
    new SecureRandom().nextBytes(value);
    return value;
  }

  public static MessageDigest findDigest(String algorithm) throws NoSuchAlgorithmException {
    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      int idx = algorithm.indexOf("-");
      if (idx > 0) {
        algorithm = algorithm.substring(0, idx) + algorithm.substring(idx + 1);
      }
      messageDigest = MessageDigest.getInstance(algorithm);
    }
    return messageDigest;
  }

  public static Mac findMac(String algorithm) {
    if (!"SHA-256".equals(algorithm)) {
      return null;
    }
    return attemptLookup("HmacSHA256");
  }

  private static Mac attemptLookup(String algorithm) {
    try {
      return Mac.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }


}
