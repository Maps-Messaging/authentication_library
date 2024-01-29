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

import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GroupPrincipalTest {

  @Test
  void testConstructorAndGetName() {
    String testName = "TestGroup";
    GroupPrincipal principal = new GroupPrincipal(testName);

    assertEquals(testName, principal.getName(), "getName should return the group name set in constructor");
  }

  @Test
  void testToString() {
    String testName = "TestGroup";
    GroupPrincipal principal = new GroupPrincipal(testName);

    String expectedString = "Group: " + testName;
    assertEquals(expectedString, principal.toString(), "toString should return the string in the correct format");
  }
}
