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

package io.mapsmessaging.security.identity.parsers;

import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

class BCryptTest extends BaseHashFunctions {

  @Test
  void checkBcryptHash() throws GeneralSecurityException, IOException {
    testHashing("$2y$10$BzVXd/hbkglo7bRLVZwYEu/45Uy24FsoZBHEaJqi690AJzIOV/Q5u", "This is an bcrypt password".toCharArray());
  }

  @Test
  void checkBcryptHashWrongPassword() throws GeneralSecurityException, IOException {
    testHashing("$2y$10$BzVXd/hbkglo7bRLVZwYEu/45Uy24FsoZBHEaJqi690AJzIOV/Q5u", "This is a wrong password".toCharArray(), false);
  }

}
