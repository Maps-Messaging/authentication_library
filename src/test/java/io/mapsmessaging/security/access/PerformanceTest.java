/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.*;

public class PerformanceTest {

  @Test
  public void testAccessControlListPerformance() {
    // Define the number of iterations and ACL entries
    int iterations = 1000000;
    List<String> aclEntries = generateAclEntries(1000);

    // Create an instance of AccessControlListManager
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), aclEntries);

    // Perform the performance test
    long startTime = System.currentTimeMillis();
    for (int i = 0; i < iterations; i++) {
      Subject subject = createRandomSubject();
      boolean hasAccess = acl.canAccess(subject, CustomAccessControlMapping.READ_VALUE);
      // Optionally, perform assertions or logging based on the hasAccess result
    }
    long endTime = System.currentTimeMillis();

    // Calculate the elapsed time
    long elapsedTime = endTime - startTime;
    System.out.println("Elapsed Time: " + elapsedTime + " ms");
  }

  private List<String> generateAclEntries(int numEntries) {
    List<String> aclEntries = new ArrayList<>();
    GroupMapManagement groupMapManagement = GroupMapManagement.getGlobalInstance();
    for (int i = 0; i < numEntries; i++) {
      String groupName = "group" + i;
      GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), groupName, "test");
      groupMapManagement.add(groupIdMap);
      String entry = groupIdMap.getAuthId() + " = Read|Write";
      aclEntries.add(entry);
    }
    return aclEntries;
  }

  private Subject createRandomSubject() {
    // Create a random subject for testing purposes
    Random random = new Random();
    String username = "user" + random.nextInt(100);
    String groupName = "group" + random.nextInt(100);
    String remoteHost = "remotehost" + random.nextInt(10);

    return createSubject(username, groupName, remoteHost);
  }

  private Subject createSubject(String username, String groupName, String remoteHost) {
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(username));
    GroupIdMap groupIdMap = GroupMapManagement.getGlobalInstance().get("test:" + groupName);
    if (groupIdMap != null) {
      principals.add(new GroupPrincipal(groupName, groupIdMap.getAuthId()));
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