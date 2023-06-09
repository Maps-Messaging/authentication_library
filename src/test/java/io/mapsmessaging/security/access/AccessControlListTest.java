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
import java.util.Set;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AccessControlListTest {

  @Test
  public void testAccessControlListCreation() {
    // Create the AccessControlList
    AccessControlListManager manager = new AccessControlListManager(new CustomAccessControlMapping());

    // Define the ACL entries
    List<String> aclEntries = new ArrayList<>();
    aclEntries.add("username = Read|Write");
    aclEntries.add("group1 = Read");
    aclEntries.add("group2@localhost = Write|Create");
    aclEntries.add("username@remotehost = Delete");

    // Create the AccessControlList
    AccessControlList acl = manager.createAccessControlList(aclEntries);

    // Create a Subject with remote host
    Subject subjectWithRemoteHost = createSubject("username", "group1", "remotehost");

    // Create a Subject without remote host
    Subject subjectWithoutRemoteHost = createSubject("username", "group1", null);

    // Test the ACL functionality
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.READ_VALUE));
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.WRITE_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.CREATE_VALUE));
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.DELETE_VALUE));

    Assertions.assertTrue(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.READ_VALUE));
    Assertions.assertTrue(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.WRITE_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.CREATE_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.DELETE_VALUE));
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
    public static final String CREATE = "create";
    public static final String DELETE = "delete";

    public static final long READ_VALUE = 1L;
    public static final long WRITE_VALUE = 2L;
    public static final long CREATE_VALUE = 4L;
    public static final long DELETE_VALUE = 8L;

    @Override
    public Long getAccessValue(String accessControl) {
      switch (accessControl.toLowerCase()) {
        case READ:
          return READ_VALUE;
        case WRITE:
          return WRITE_VALUE;
        case CREATE:
          return CREATE_VALUE;
        case DELETE:
          return DELETE_VALUE;
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
