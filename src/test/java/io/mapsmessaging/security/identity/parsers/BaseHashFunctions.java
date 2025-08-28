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

package io.mapsmessaging.security.identity.parsers;

import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;

public class BaseHashFunctions {

  protected void testHashing(String passwordHashString, char[] rawPassword)
      throws GeneralSecurityException, IOException {
    testHashing(passwordHashString, rawPassword, true);
  }

  protected void testHashing(String passwordHashString, char[] rawPassword, boolean shouldPass)
      throws GeneralSecurityException, IOException {
    //
    // We parse the password string to extract the public SALT, so we can pass to the client
    //
    PasswordHandler passwordHasher = PasswordHandlerFactory.getInstance().parse(passwordHashString.toCharArray());

    // This would be done on the client side of this
    char[] hash =
        passwordHasher.transformPassword(
            rawPassword,
            passwordHasher.getSalt(),
            passwordHasher.getCost());

    // The result should be that the hash = password + salt hashed should match what the server has
    if (shouldPass) {
      Assertions.assertArrayEquals(passwordHashString.toCharArray(), hash);
    } else {
      Assertions.assertFalse(Arrays.equals(passwordHashString.toCharArray(), hash));
    }
  }

}
