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

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.authorisation.impl.acl.AccessControlList;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.impl.apache.HtPasswdEntry;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import io.mapsmessaging.security.uuid.UuidGenerator;
import java.security.Principal;
import java.util.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PermissiveAccessTest extends BaseSecurityTest {

  private static final String[] users = {"user1", "user2", "user3"};
  private static final String[] groups = {"group1"};
  private static final String[] access = {"read|write", "read", "write"};

  private final Map<String, UUID> userUUIDMap = new LinkedHashMap<>();
  private final Map<String, Identity> subjectMap = new LinkedHashMap<>();

  @Test
  void validate(){
    AccessControlList accessControlList = new AccessControlList(createList());
    Assertions.assertEquals(4, userUUIDMap.size());
    buildUser("user4");
    accessControlList.addUser(userUUIDMap.get("user4"), 3);
    Assertions.assertSame(accessControlList.canAccess(subjectMap.get("user1"), 1), Access.ALLOW);
    Assertions.assertSame(accessControlList.canAccess(subjectMap.get("user4"), 1), Access.ALLOW);
    Assertions.assertTrue(accessControlList.remove(userUUIDMap.get("user4"), 3));
    Assertions.assertSame(accessControlList.canAccess(subjectMap.get("user4"), 1), Access.ALLOW); // Groups should allow access
    Assertions.assertEquals(3, accessControlList.getSubjectAccess(subjectMap.get("user1")));
    Assertions.assertEquals(3, accessControlList.getSubjectAccess(subjectMap.get("user2")));
  }


  private Identity createSubject(String username) {
    GroupIdMap groupIdMap = new GroupIdMap(userUUIDMap.get(groups[0]), username, "");
    List<GroupIdMap> groupList = new ArrayList<>();
    groupList.add(groupIdMap);
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(username));
    principals.add(new UniqueIdentifierPrincipal(userUUIDMap.get(username)));
    principals.add(new GroupIdPrincipal(groupList));
    GroupEntry entry = new GroupEntry(groupIdMap.getGroupName(), new HashSet<>());
    List<Group> list = new ArrayList<>();
    Group group = new Group(groupIdMap.getAuthId(), entry);
    list.add(group);
    IdentityEntry identityEntry = new HtPasswdEntry(username, new char[0]);

    return new Identity(userUUIDMap.get(username),identityEntry , list );
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
