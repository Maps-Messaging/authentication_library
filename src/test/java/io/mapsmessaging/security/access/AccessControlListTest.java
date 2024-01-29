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

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapFileStore;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.bcrypt.BCrypt2YPasswordHasher;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.*;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AccessControlListTest {

  @Test
  public void testAccessControlListCreation() throws IOException, GeneralSecurityException {
    File file = new File("./target/test/security");
    file.mkdirs();
    MapStore<UserIdMap> userStore = new MapFileStore<>("./target/test/security/userMap");
    MapStore<GroupIdMap> groupStore = new MapFileStore<>("./target/test/security/groupMap");

    IdentityAccessManager identityAccessManager =
        new IdentityAccessManager(
            "Apache-Basic-Auth",
            Collections.singletonMap("configDirectory", "./target/test/security"),
            userStore,
            groupStore);

    PasswordHasher passwordHasher = new BCrypt2YPasswordHasher();
    identityAccessManager.setPasswordHandler(passwordHasher);

    byte[] hash =
        passwordHasher.transformPassword(
            "password1".getBytes(StandardCharsets.UTF_8),
            PasswordGenerator.generateSalt(16).getBytes(StandardCharsets.UTF_8),
            10);
    UserIdMap usernameId = identityAccessManager.createUser("username", new String(hash));

    hash =
        passwordHasher.transformPassword(
            "password2".getBytes(StandardCharsets.UTF_8),
            PasswordGenerator.generateSalt(16).getBytes(StandardCharsets.UTF_8),
            10);
    UserIdMap username2Id = identityAccessManager.createUser("username2", new String(hash));

    hash =
        passwordHasher.transformPassword(
            "password3".getBytes(StandardCharsets.UTF_8),
            PasswordGenerator.generateSalt(16).getBytes(StandardCharsets.UTF_8),
            10);
    UserIdMap fredId = identityAccessManager.createUser("fred", new String(hash));

    GroupIdMap group1IdMap = identityAccessManager.createGroup("group1");
    GroupIdMap group2IdMap = identityAccessManager.createGroup("group2");

    identityAccessManager.addUserToGroup("username", "group1");
    // identityAccessManager.addUserToGroup("username", "group2");
    identityAccessManager.addUserToGroup("username2", "group2");

    // Create the AccessControlList
    List<String> aclEntries = new ArrayList<>();
    aclEntries.add(usernameId.getAuthId() + " = Read|Write");
    aclEntries.add(username2Id.getAuthId() + " = Read|Write");
    aclEntries.add(group2IdMap.getAuthId() + " = Read|Write");
    aclEntries.add(group1IdMap.getAuthId() + " = Delete");
    aclEntries.add(fredId.getAuthId() + " = Write|Read|Delete");

    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), aclEntries);

    // Create a Subject with remote host
    Subject subjectWithRemoteHost = createSubject(usernameId);
    subjectWithRemoteHost = identityAccessManager.updateSubject(subjectWithRemoteHost);

    // Create a Subject without remote host
    Subject subjectWithoutRemoteHost = createSubject(username2Id);
    subjectWithoutRemoteHost = identityAccessManager.updateSubject(subjectWithoutRemoteHost);

    Subject subjectWithAuthDomain = createSubject(username2Id);
    subjectWithAuthDomain = identityAccessManager.updateSubject(subjectWithAuthDomain);

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
    MapStore<UserIdMap> userStore = new MapFileStore<>("./src/test/resources/users.txt");
    MapStore<GroupIdMap> groupStore = new MapFileStore<>("./src/test/resources/groups.txt");

    UserMapManagement userMapManagement = new UserMapManagement(userStore);
    GroupMapManagement groupMapManagement = new GroupMapManagement(groupStore);

    UserIdMap userIdMap = new UserIdMap(UUID.randomUUID(), "user1", "test");
    GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), "group1", "test");

    userMapManagement.add(userIdMap);
    groupMapManagement.add(groupIdMap);

    // Create a subject with necessary principals
    Subject subject = new Subject();
    subject.getPrincipals().add(new UserPrincipal("user1"));
    subject.getPrincipals().add(new GroupPrincipal("group1"));
    subject.getPrincipals().add(new UniqueIdentifierPrincipal(userIdMap.getAuthId()));
    // Set up the access control list with the necessary ACL entries
    List<String> aclEntries = Collections.singletonList(userIdMap.getAuthId() + " = Read|Write");

    AccessControlMapping accessControlMapping = new CustomAccessControlMapping();
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), aclEntries);
    // Requested access that should be allowed
    long requestedAccess = accessControlMapping.getAccessValue("Read");

    // Verify that the subject can access with the requested access
    Assertions.assertTrue(acl.canAccess(subject, requestedAccess));

    userMapManagement.clearAll();
    Assertions.assertEquals(0, userMapManagement.size());

    groupMapManagement.clearAll();
    Assertions.assertEquals(0, groupMapManagement.size());
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
    subject.getPrincipals().add(new GroupPrincipal("group1"));

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
    subject.getPrincipals().add(new GroupPrincipal("group1"));

    // Set up the access control list with invalid ACL entry
    List<String> aclEntries = Collections.singletonList("invalidEntry");
    AccessControlMapping accessControlMapping = new CustomAccessControlMapping();
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new CustomAccessControlMapping(), new ArrayList<>());


    // Requested access
    long requestedAccess = accessControlMapping.getAccessValue("Read");

    // Verify that the subject is not allowed to access with invalid ACL entry
    Assertions.assertFalse(acl.canAccess(subject, requestedAccess));
  }

  private Subject createSubject(UserIdMap user) {
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(user.getUsername()));
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
