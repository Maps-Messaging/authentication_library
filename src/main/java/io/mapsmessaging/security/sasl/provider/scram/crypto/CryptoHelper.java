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

package io.mapsmessaging.security.sasl.provider.scram.crypto;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoHelper {

  private CryptoHelper() {
    // This is a helper class and does not have any instance methods
  }

  public static String generateNonce(int size) {
    SecureRandom prng = new SecureRandom();
    byte[] nonce = new byte[size];
    prng.nextBytes(nonce);
    return Base64.getEncoder().encodeToString(nonce);
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
    String macLookup = "Hmac" + algorithm.toUpperCase().trim();
    Mac mac;
    mac = attemptLookup(macLookup);
    if (mac == null) {
      int idx = macLookup.indexOf("-");
      if (idx > 0) {
        macLookup = macLookup.substring(0, idx) + macLookup.substring(idx + 1);
        mac = attemptLookup(macLookup);
      }
    }
    return mac;
  }

  private static Mac attemptLookup(String algorithm) {
    try {
      return Mac.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }


}
