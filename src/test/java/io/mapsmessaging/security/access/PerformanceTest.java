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

import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapFileStore;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import java.util.List;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Test;

public class PerformanceTest extends BaseSecurityTest {

  @Test
  public void testAccessControlListPerformance() {
    // Define the number of iterations and ACL entries
    int iterations = 1000000;
    MapStore<GroupIdMap> groupStore = new MapFileStore<>("./src/test/resources/groups.txt");
    GroupMapManagement groupMapManagement = new GroupMapManagement(groupStore);
    List<String> aclEntries = generateGroupEntries(1000, groupMapManagement);

    // Create an instance of AccessControlListManager
    AccessControlList acl =
        AccessControlFactory.getInstance().get(
            "Permission",
            new CustomAccessControlMapping(),
            aclEntries);

    // Perform the performance test
    long startTime = System.currentTimeMillis();
    for (int i = 0; i < iterations; i++) {
      Subject subject = createRandomSubject(groupMapManagement);
      boolean hasAccess = acl.canAccess(subject, CustomAccessControlMapping.READ_VALUE);
      // Optionally, perform assertions or logging based on the hasAccess result
    }
    long endTime = System.currentTimeMillis();

    // Calculate the elapsed time
    long elapsedTime = endTime - startTime;
    System.out.println("Elapsed Time: " + elapsedTime + " ms");
  }
}