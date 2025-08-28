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

package io.mapsmessaging.security.identity;
import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UniqueIdentifierPrincipalTest {

  @Test
  void testConstructorAndAuthIdGetter() {
    UUID testAuthId = UUID.randomUUID();
    UniqueIdentifierPrincipal principal = new UniqueIdentifierPrincipal(testAuthId);

    assertEquals(testAuthId, principal.getAuthId(), "authId should match the one set in constructor");
  }

  @Test
  void testGetName() {
    UUID testAuthId = UUID.randomUUID();
    UniqueIdentifierPrincipal principal = new UniqueIdentifierPrincipal(testAuthId);

    assertEquals(testAuthId.toString(), principal.getName(), "getName should return authId's string representation");
  }

  @Test
  void testToString() {
    UUID testAuthId = UUID.randomUUID();
    UniqueIdentifierPrincipal principal = new UniqueIdentifierPrincipal(testAuthId);

    String expectedString = "Unique Id : " + testAuthId;
    assertEquals(expectedString, principal.toString(), "toString should return the string in the correct format");
  }
}
