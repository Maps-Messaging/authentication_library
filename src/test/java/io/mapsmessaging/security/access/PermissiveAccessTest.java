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

package io.mapsmessaging.security.access;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import io.mapsmessaging.security.uuid.UuidGenerator;
import java.security.Principal;
import java.util.*;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PermissiveAccessTest extends BaseSecurityTest {

  private static final String[] users = {"user1", "user2", "user3"};
  private static final String[] groups = {"group1"};
  private static final String[] access = {"read|write", "read", "write"};

  private final Map<String, UUID> userUUIDMap = new LinkedHashMap<>();
  private final Map<String, Subject> subjectMap = new LinkedHashMap<>();

  @Test
  void validate(){
    AccessControlList accessControlList = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(),createList());
    Assertions.assertEquals("permission", accessControlList.getName());
    Assertions.assertEquals(4, userUUIDMap.size());
    buildUser("user4");
    accessControlList.add(userUUIDMap.get("user4"), 3);
    Assertions.assertTrue(accessControlList.canAccess(subjectMap.get("user1"), 1) );
    Assertions.assertTrue(accessControlList.canAccess(subjectMap.get("user4"), 1) );
    Assertions.assertTrue(accessControlList.remove(userUUIDMap.get("user4"), 3));
    Assertions.assertTrue(accessControlList.canAccess(subjectMap.get("user4"), 1) ); // Groups should allow access
    Assertions.assertEquals(3, accessControlList.getSubjectAccess(subjectMap.get("user1")));
    Assertions.assertEquals(3, accessControlList.getSubjectAccess(subjectMap.get("user2")));
  }


  private Subject createSubject(String username) {
    GroupIdMap groupIdMap = new GroupIdMap(userUUIDMap.get(groups[0]), username, "");
    List<GroupIdMap> groupList = new ArrayList<>();
    groupList.add(groupIdMap);
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(username));
    principals.add(new UniqueIdentifierPrincipal(userUUIDMap.get(username)));
    principals.add(new GroupIdPrincipal(groupList));
    return new Subject(true, principals, new HashSet<>(), new HashSet<>());
  }

  private void buildUser(String username){
    UUID uuid = UuidGenerator.getInstance().generate();
    userUUIDMap.put(username, uuid);
    createSubject(username);
    subjectMap.put(username, createSubject(username));
  }

  private void buildGroup(String groupName){
    UUID uuid = UuidGenerator.getInstance().generate();
    userUUIDMap.put(groupName, uuid);
  }

  List<String> createList(){
    List<String> list = new ArrayList<>();
    for(int x=0;x<groups.length;x++){
      buildGroup(groups[x]);
      list.add(userUUIDMap.get(groups[x])+"="+access[0]);
    }
    for(int x=0;x<users.length;x++){
      buildUser(users[x]);
      list.add(userUUIDMap.get(users[x])+"="+access[x]);
    }

    return list;
  }
}
