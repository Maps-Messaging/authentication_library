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

package io.mapsmessaging.security.identity.parsers;

import org.junit.jupiter.api.Assertions;

public class BaseTest {

  protected void testHashing(String passwordHashString, String rawPassword){
    //
    // We parse the password string to extract the public SALT, so we can pass to the client
    //
    PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(passwordHashString);


    // This would be done on the client side of this
    byte[] hash = passwordParser.computeHash(rawPassword.getBytes(), passwordParser.getSalt(), passwordParser.getCost());

    // The result should be that the hash = password + salt hashed should match what the server has
    Assertions.assertArrayEquals(passwordHashString.toCharArray(), new String(hash).toCharArray());
  }

}
