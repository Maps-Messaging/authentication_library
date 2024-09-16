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

package io.mapsmessaging.security.access.mapping;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class DomainIdMappingTest {

  @Test
  void testConstructorAndGetters() {
    UUID testAuthId = UUID.randomUUID();
    String testId = "testId";
    String testAuthDomain = "testAuthDomain";

    DomainIdMapping mapping = new DomainIdMapping(testAuthId, testId, testAuthDomain);

    assertEquals(testAuthDomain, mapping.getAuthDomain(), "AuthDomain should match the one set in constructor");
    // Assuming there's a getter for authId in IdMap
    assertEquals(testAuthId, mapping.getAuthId(), "AuthId should match the one set in constructor");
    // Direct access to 'id' if it's visible in the test context
    assertEquals(testId, mapping.getId(), "Id should match the one set in constructor");
  }

  @Test
  void testGetKey() {
    UUID testAuthId = UUID.randomUUID();
    String testId = "testId";
    String testAuthDomain = "testAuthDomain";

    DomainIdMapping mapping = new DomainIdMapping(testAuthId, testId, testAuthDomain);

    String expectedKey = testAuthDomain + ":" + testId;
    assertEquals(expectedKey, mapping.getKey(), "getKey should return the correct composite key");
  }

  @Test
  void testEqualsAndHashCode() {
    UUID testAuthId = UUID.randomUUID();
    String testId = "testId";
    String testAuthDomain = "testAuthDomain";

    DomainIdMapping mapping1 = new DomainIdMapping(testAuthId, testId, testAuthDomain);
    DomainIdMapping mapping2 = new DomainIdMapping(testAuthId, testId, testAuthDomain);

    assertEquals(mapping1, mapping2, "Two instances with the same authId, id, and authDomain should be equal");
    assertEquals(mapping1.hashCode(), mapping2.hashCode(), "Hash codes should be equal for equal objects");
  }

  // Additional tests can be added if there are more behaviors or methods to be tested
}
