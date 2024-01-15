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

package io.mapsmessaging.security.identity.parsers;

import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;

public class BaseHashFunctions {

  protected void testHashing(String passwordHashString, String rawPassword) {
    testHashing(passwordHashString, rawPassword, true);
  }

  protected void testHashing(String passwordHashString, String rawPassword, boolean shouldPass) {
    //
    // We parse the password string to extract the public SALT, so we can pass to the client
    //
    PasswordHandler passwordHasher = PasswordHandlerFactory.getInstance().parse(passwordHashString);

    // This would be done on the client side of this
    byte[] hash =
        passwordHasher.transformPassword(
            rawPassword.getBytes(StandardCharsets.UTF_8),
            passwordHasher.getSalt(),
            passwordHasher.getCost());

    // The result should be that the hash = password + salt hashed should match what the server has
    if (shouldPass) {
      Assertions.assertArrayEquals(passwordHashString.getBytes(StandardCharsets.UTF_8), hash);
    } else {
      Assertions.assertFalse(Arrays.equals(passwordHashString.getBytes(StandardCharsets.UTF_8), hash));
    }
  }

}
