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
import io.mapsmessaging.security.identity.IdentityAuthorisationManager;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import java.security.Principal;
import java.util.*;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AccessControlListTest {

  @Test
  public void testAccessControlListCreation() {
    IdentityAuthorisationManager identityAuthorisationManager = new IdentityAuthorisationManager();

    // Create the AccessControlList
    List<String> aclEntries = new ArrayList<>();
    aclEntries.add("username = Read|Write");
    aclEntries.add("unix:username2 = Read|Write");
    aclEntries.add("group1 = Read");
    aclEntries.add("group2[localhost] = Write|Create");
    aclEntries.add("username[remotehost] = Delete");
    aclEntries.add("ldap:fred[remotehost2] = Write|Read|Delete");
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), aclEntries);

    // Create a Subject with remote host
    Subject subjectWithRemoteHost = createSubject("username", "group1", "remotehost");
    subjectWithRemoteHost.getPrincipals().add(new UniqueIdentifierPrincipal(UUID.randomUUID()));
    identityAuthorisationManager.setAuthId(subjectWithRemoteHost);

    // Create a Subject without remote host
    Subject subjectWithoutRemoteHost = createSubject("username", "group1", null);
    subjectWithoutRemoteHost.getPrincipals().add(new UniqueIdentifierPrincipal(UUID.randomUUID()));
    identityAuthorisationManager.setAuthId(subjectWithoutRemoteHost);

    Subject subjectWithAuthDomain = createSubject("username2", "group1", "remotehost");
    subjectWithAuthDomain.getPrincipals().add(new AuthHandlerPrincipal("unix"));
    subjectWithAuthDomain.getPrincipals().add(new UniqueIdentifierPrincipal(UUID.randomUUID()));
    identityAuthorisationManager.setAuthId(subjectWithAuthDomain);

    long test = acl.getSubjectAccess(subjectWithRemoteHost);
    Assertions.assertTrue((test & CustomAccessControlMapping.READ_VALUE) != 0);
    Assertions.assertTrue((test & CustomAccessControlMapping.WRITE_VALUE) != 0);
    Assertions.assertTrue((test & CustomAccessControlMapping.DELETE_VALUE) != 0);
    Assertions.assertEquals(11, test);

    // Test the ACL functionality
    Assertions.assertTrue(acl.canAccess(subjectWithAuthDomain, CustomAccessControlMapping.READ_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithAuthDomain, CustomAccessControlMapping.DELETE_VALUE));

    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.READ_VALUE));
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.WRITE_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.CREATE_VALUE));
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, CustomAccessControlMapping.DELETE_VALUE));

    Assertions.assertTrue(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.READ_VALUE));
    Assertions.assertTrue(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.WRITE_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.CREATE_VALUE));
    Assertions.assertFalse(acl.canAccess(subjectWithoutRemoteHost, CustomAccessControlMapping.DELETE_VALUE));
  }

  @Test
  void testCanAccess_ValidAccess_ReturnsTrue() {
    // Create a subject with necessary principals
    Subject subject = new Subject();
    subject.getPrincipals().add(new UserPrincipal("user1"));
    subject.getPrincipals().add(new GroupPrincipal("group1", UUID.randomUUID()));
    // Set up the access control list with the necessary ACL entries
    List<String> aclEntries = Collections.singletonList("user1 = Read|Write");

    AccessControlMapping accessControlMapping = new CustomAccessControlMapping();
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), aclEntries);
    // Requested access that should be allowed
    long requestedAccess = accessControlMapping.getAccessValue("Read");

    // Verify that the subject can access with the requested access
    Assertions.assertTrue(acl.canAccess(subject, requestedAccess));
  }

  @Test
  void testCanAccess_NullSubject_ReturnsFalse() {
    // Null subject
    Subject subject = null;
    AccessControlMapping accessControlMapping = new CustomAccessControlMapping();
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), new ArrayList<>());

    // Requested access
    long requestedAccess = accessControlMapping.getAccessValue("Read");

    // Verify that the null subject is not allowed to access
    Assertions.assertFalse(acl.canAccess(subject, requestedAccess));
  }

  @Test
  void testCanAccess_NullAccess_ReturnsFalse() {
    // Create a subject with necessary principals
    Subject subject = new Subject();
    subject.getPrincipals().add(new UserPrincipal("user1"));
    subject.getPrincipals().add(new GroupPrincipal("group1", UUID.randomUUID()));

    // Set up the access control list with the necessary ACL entries
    List<String> aclEntries = Collections.singletonList("user1 = Read|Write");
    AccessControlMapping accessControlMapping = new CustomAccessControlMapping();
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), new ArrayList<>());

    // Null requested access
    long requestedAccess = accessControlMapping.getAccessValue(null);

    // Verify that the subject is not allowed to access with null access
    Assertions.assertFalse(acl.canAccess(subject, requestedAccess));
  }

  @Test
  void testCanAccess_InvalidEntry_ReturnsFalse() {
    // Create a subject with necessary principals
    Subject subject = new Subject();
    subject.getPrincipals().add(new UserPrincipal("user1"));
    subject.getPrincipals().add(new GroupPrincipal("group1", UUID.randomUUID()));

    // Set up the access control list with invalid ACL entry
    List<String> aclEntries = Collections.singletonList("invalidEntry");
    AccessControlMapping accessControlMapping = new CustomAccessControlMapping();
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), new ArrayList<>());


    // Requested access
    long requestedAccess = accessControlMapping.getAccessValue("Read");

    // Verify that the subject is not allowed to access with invalid ACL entry
    Assertions.assertFalse(acl.canAccess(subject, requestedAccess));
  }

  private Subject createSubject(String username, String groupName, String remoteHost) {
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(username));
    principals.add(new GroupPrincipal(groupName, UUID.randomUUID()));
    if (remoteHost != null) {
      principals.add(new RemoteHostPrincipal(remoteHost));
    }

    return new Subject(false, principals, new HashSet<>(), new HashSet<>());
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
      if(accessControl == null){
        return 0L;
      }
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
