/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Arrays;

/** Local password-format demonstration; never deploy the demonstration password. */
public final class PasswordExample {
  private PasswordExample() {
  }

  public static void main(String[] arguments) throws Exception {
    char[] password = "example-password".toCharArray();
    char[] wrongPassword = "wrong-password".toCharArray();
    char[] encoded = null;
    byte[] entropy = new byte[8];
    new SecureRandom().nextBytes(entropy);
    byte[] salt = HexFormat.of().formatHex(entropy).getBytes(StandardCharsets.US_ASCII);
    try {
      PasswordHandlerFactory factory = PasswordHandlerFactory.getInstance();
      PasswordHandler hasher = factory.getByClassName("UnixSha512PasswordHasher");
      if (hasher == null) {
        throw new IllegalStateException("SHA-512-crypt provider missing; preserve META-INF/services in your application packaging");
      }
      // This implementation uses the crypt format's rounds, not the generic cost parameter.
      encoded = hasher.transformPassword(password, salt, hasher.getCost());
      PasswordHandler stored = factory.parse(encoded);
      if (!stored.matches(password) || stored.matches(wrongPassword)) {
        throw new IllegalStateException("Password verification did not match the expected result");
      }
      System.out.println("Password hash verified; incorrect password rejected");
    } finally {
      Arrays.fill(password, '\0');
      Arrays.fill(wrongPassword, '\0');
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(entropy, (byte) 0);
      if (encoded != null) {
        Arrays.fill(encoded, '\0');
      }
    }
  }
}
