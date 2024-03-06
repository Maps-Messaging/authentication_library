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

package io.mapsmessaging.security.access;

import com.github.javafaker.Faker;
import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import java.security.Principal;
import java.util.*;
import javax.security.auth.Subject;

public class BaseSecurityTest {

  protected List<String> generateUserEntries(int numEntries, UserMapManagement userMapManagement, GroupMapManagement groupMapManagement) {
    List<String> aclEntries = new ArrayList<>();
    Faker faker = new Faker();
    for (int i = 0; i < numEntries; i++) {
      UserIdMap userIdMap = new UserIdMap(UUID.randomUUID(), faker.name().username(), "test");
      userMapManagement.add(userIdMap);
      String entry = userIdMap.getAuthId() + " = Read|Write|Delete";
      aclEntries.add(entry);
    }
    return aclEntries;
  }

  protected List<String> generateGroupEntries(int numEntries, GroupMapManagement groupMapManagement) {
    List<String> aclEntries = new ArrayList<>();
    Faker faker = new Faker();
    for (int i = 0; i < numEntries; i++) {
      String groupName = faker.space().nebula() + "-" + faker.space().galaxy();
      GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), groupName, "test");
      groupMapManagement.add(groupIdMap);
      String entry = groupIdMap.getAuthId() + " = Read|Write";
      aclEntries.add(entry);
    }
    return aclEntries;
  }


  protected Subject createRandomSubject(GroupMapManagement groupMapManagement) {
    // Create a random subject for testing purposes
    Random random = new Random();
    String username = "user" + random.nextInt(100);
    String groupName = "group" + random.nextInt(100);
    String remoteHost = "remotehost" + random.nextInt(10);

    return createSubject(groupMapManagement, username, groupName, remoteHost);
  }

  protected Subject createSubject(GroupMapManagement groupMapManagement,
                                  String username,
                                  String groupName,
                                  String remoteHost) {
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(username));
    GroupIdMap groupIdMap = groupMapManagement.get("test:" + groupName);
    if (groupIdMap != null) {
      principals.add(new GroupPrincipal(groupName));
    }
    if (remoteHost != null) {
      principals.add(new RemoteHostPrincipal(remoteHost));
    }
    return new Subject(true, principals, new HashSet<>(), new HashSet<>());
  }

  // Custom AccessControlMapping implementation
  public static class CustomAccessControlMapping implements AccessControlMapping {
    // Access control keywords and corresponding bitset values
    public static final String READ = "read";
    public static final String WRITE = "write";

    public static final long READ_VALUE = 1L;
    public static final long WRITE_VALUE = 2L;

    @Override
    public Long getAccessValue(String accessControl) {
      switch (accessControl.toLowerCase()) {
        case READ:
          return READ_VALUE;
        case WRITE:
          return WRITE_VALUE;
        default:
          return null;
      }
    }

    @Override
    public String getAccessName(long value) {
      return null;
    }
  }
}
