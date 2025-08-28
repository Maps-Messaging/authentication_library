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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import io.mapsmessaging.security.uuid.UuidGenerator;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class GroupIdPrincipalTest {

  @Test
  void testConstructorAndGroupIdsGetter() {
    /* create test GroupIdMap instances */
    List<GroupIdMap> testGroupIds = List.of();
    GroupIdPrincipal principal = new GroupIdPrincipal(testGroupIds);

    assertEquals(testGroupIds, principal.getGroupIds(), "groupIds should match the ones set in constructor");
  }

  @Test
  void testGetName() {
    /* create test GroupIdMap instances */
    GroupIdPrincipal principal = new GroupIdPrincipal(List.of());
    assertEquals("GroupIds", principal.getName(), "getName should return 'GroupIds'");
  }

  @Test
  void testToString() {
    GroupIdMap groupId1 = new GroupIdMap(UuidGenerator.getInstance().generate(), "group1", "myAuth");
    GroupIdMap groupId2 = new GroupIdMap(UuidGenerator.getInstance().generate(), "group2", "myAuth");
    List<GroupIdMap> testGroupIds = Arrays.asList(groupId1, groupId2);
    GroupIdPrincipal principal = new GroupIdPrincipal(testGroupIds);

    String expectedString = "Group Ids:\n\t" + groupId1 + "\n\t" + groupId2;
    assertEquals(expectedString, principal.toString(), "toString should format groupIds correctly");
    List<GroupIdMap> testGroupIds2 = Arrays.asList(groupId1, groupId2);
    assertArrayEquals(testGroupIds.toArray(new GroupIdMap[0]), testGroupIds2.toArray());
  }
}
