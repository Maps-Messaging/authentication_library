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
import io.mapsmessaging.security.authorisation.impl.acl.AccessControlFactory;
import io.mapsmessaging.security.authorisation.impl.acl.AccessControlList;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.security.auth.Subject;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class AccessControlJHMTest {

  @Param({"1000"})
  private int numEntries;

  @Param({"1000000"})
  private int numIterations;

  private AccessControlList acl;
  private Subject[] subjects;

  public static void main(String[] args) throws RunnerException {
    Options options = new OptionsBuilder()
        .include(AccessControlJHMTest.class.getSimpleName())
        .forks(1)
        .build();

    new Runner(options).run();
  }

  @Setup
  public void setup() {
    // Define the ACL entries
    List<String> aclEntries = generateAclEntries(numEntries);

    // Create the AccessControlList
    acl = AccessControlFactory.getInstance().get("Permission", aclEntries);

    // Create the subjects for testing
    subjects = new Subject[numIterations];
    for (int i = 0; i < numIterations; i++) {
      subjects[i] = createRandomSubject();
    }
  }

  @Benchmark
  public void testAccessControlListPerformance() {
    for (int i = 0; i < numIterations; i++) {
      boolean hasAccess = acl.canAccess(subjects[i], TestPermissions.READ.getMask());
      // Optionally, perform assertions or logging based on the hasAccess result
    }
  }

  private List<String> generateAclEntries(int numEntries) {
    List<String> aclEntries = new ArrayList<>();
    for (int i = 0; i < numEntries; i++) {
      String entry = UUID.randomUUID() + " = Read|Write";
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

}
