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

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserMapParsingTest {

  @Test
  void testCreateMappingValidFormat() {
    String validIdentifier = "123e4567-e89b-12d3-a456-426614174000 = authDomain:username";
    UserMapParser parser = new UserMapParser();

    UserIdMap userIdMap = parser.createMapping(validIdentifier);

    assertNotNull(userIdMap, "Parsed UserIdMap should not be null");
    assertEquals(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"), userIdMap.getAuthId(), "AuthId should match the UUID in the identifier");
    assertEquals("authDomain", userIdMap.getAuthDomain(), "AuthDomain should match the authDomain in the identifier");
    assertEquals("username", userIdMap.getUsername(), "Username should match the username in the identifier");
  }

  @Test
  void testCreateMappingInvalidFormat() {
    String invalidIdentifier = "invalidFormat";
    UserMapParser parser = new UserMapParser();

    assertThrows(IllegalArgumentException.class, () -> parser.createMapping(invalidIdentifier), "Invalid format should throw IllegalArgumentException");
  }

  @Test
  void testCreateListAndWriteToList() {
    List<String> identifiers = Arrays.asList("123e4567-e89b-12d3-a456-426614174000 = authDomain1:username1", "123e4567-e89b-12d3-a456-426614174001 = authDomain2:username2");
    UserMapParser parser = new UserMapParser();

    List<UserIdMap> userIdMaps = parser.createList(identifiers);
    assertEquals(2, userIdMaps.size(), "Should create two UserIdMap instances");

    List<String> serializedList = parser.writeToList(userIdMaps);
    assertTrue(serializedList.containsAll(identifiers), "Serialized list should contain all original identifiers");
  }

}

