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
import java.util.concurrent.TimeUnit;
import javax.security.auth.Subject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
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
    acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), aclEntries);

    // Create the subjects for testing
    subjects = new Subject[numIterations];
    for (int i = 0; i < numIterations; i++) {
      subjects[i] = createRandomSubject();
    }
  }

  @Benchmark
  public void testAccessControlListPerformance() {
    for (int i = 0; i < numIterations; i++) {
      boolean hasAccess = acl.canAccess(subjects[i], CustomAccessControlMapping.READ_VALUE);
      // Optionally, perform assertions or logging based on the hasAccess result
    }
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
    public static final String READ = "Read";
    public static final String WRITE = "Write";

    public static final long READ_VALUE = 1L;
    public static final long WRITE_VALUE = 2L;

    @Override
    public Long getAccessValue(String accessControl) {
      switch (accessControl) {
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
