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
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Test;

public class PerformanceTest {

  @Test
  public void testAccessControlListPerformance() {
    // Define the number of iterations and ACL entries
    int iterations = 1000000;
    List<String> aclEntries = generateAclEntries(1000);

    // Create an instance of AccessControlListManager
    AccessControlListManager manager = new AccessControlListManager(new CustomAccessControlMapping());

    // Create the AccessControlList
    AccessControlList acl = manager.createAccessControlList(aclEntries);

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
    for (int i = 0; i < numEntries; i++) {
      String entry = "group" + i + " = Read|Write";
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
    principals.add(new GroupPrincipal(groupName));
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