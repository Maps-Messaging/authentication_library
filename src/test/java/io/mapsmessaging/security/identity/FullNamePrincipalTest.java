/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.identity;

import io.mapsmessaging.security.identity.principals.FullNamePrincipal;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FullNamePrincipalTest {

  @Test
  void testConstructorAndGetName() {
    String testFullName = "John Doe";
    FullNamePrincipal principal = new FullNamePrincipal(testFullName);

    assertEquals(testFullName, principal.getName(), "getName should return the full name set in constructor");
  }

  @Test
  void testToString() {
    String testFullName = "John Doe";
    FullNamePrincipal principal = new FullNamePrincipal(testFullName);

    String expectedString = "Full Name: " + testFullName;
    assertEquals(expectedString, principal.toString(), "toString should return the string in the correct format");
  }
}