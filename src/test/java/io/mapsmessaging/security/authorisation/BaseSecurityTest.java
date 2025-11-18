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

package io.mapsmessaging.security.authorisation;

import com.github.javafaker.Faker;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.impl.apache.HtPasswdEntry;
import java.util.*;
import org.junit.jupiter.api.BeforeAll;

public class BaseSecurityTest {
  private static final Faker faker = new Faker();

  @BeforeAll
  static void setUp() {
    PermissionRegistry.registerAll(TestPermissions.values());
  }

  protected List<String> generateGroupEntries(int numEntries, GroupMapManagement groupMapManagement) {
    List<String> aclEntries = new ArrayList<>();
    for (int i = 0; i < numEntries; i++) {
      String groupName = faker.space().nebula() + "-" + faker.space().galaxy();
      GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), groupName, "test");
      groupMapManagement.add(groupIdMap);
      String entry = groupIdMap.getAuthId() + " = Read|Write";
      aclEntries.add(entry);
    }
    return aclEntries;
  }

  public static Identity createRandomIdenties(GroupMapManagement groupMapManagement) {
    Random random = new Random();
    String username = faker.name().firstName();
    String groupName = "group" + random.nextInt(100);
    return createIdentity(groupMapManagement,username,  groupName);
  }

  public static Identity createIdentity(GroupMapManagement groupMapManagement, String username, String groupName) {
    List<Group> groups = new ArrayList<>();
    if (groupMapManagement != null) {
      GroupIdMap groupIdMap = groupMapManagement.get("test:" + groupName);
      if (groupIdMap != null) {
        GroupEntry entry = new GroupEntry(groupIdMap.getGroupName(), new HashSet<>());

        Group group = new Group(groupIdMap.getAuthId(), entry);
        groups.add(group);
      }
    }
    IdentityEntry identityEntry = new HtPasswdEntry(username, new char[0]);
    return new Identity(UUID.randomUUID(), identityEntry, groups);
  }

}
