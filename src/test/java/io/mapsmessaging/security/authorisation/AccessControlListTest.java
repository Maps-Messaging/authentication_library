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
import io.mapsmessaging.security.access.IdentityAccessManager;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapFileStore;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import io.mapsmessaging.security.authorisation.impl.acl.AccessControlFactory;
import io.mapsmessaging.security.authorisation.impl.acl.AccessControlList;
import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import io.mapsmessaging.security.passwords.PasswordHandler;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.*;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class AccessControlListTest {

  @BeforeAll
  static void setUp() {
    PermissionRegistry.registerAll(TestPermissions.values());
  }

  @Test
  public void testAccessControlListCreation() throws IOException, GeneralSecurityException {
    File file = new File("./target/test/security");
    file.mkdirs();
    MapStore<UserIdMap> userStore = new MapFileStore<>("./target/test/security/userMap");
    MapStore<GroupIdMap> groupStore = new MapFileStore<>("./target/test/security/groupMap");

    Map<String, Object> config = new LinkedHashMap<>();
    config.put("configDirectory", "./target/test/security");
    config.put("passwordHandler", "BCrypt2YPasswordHasher");

    IdentityAccessManager identityAccessManager =
        new IdentityAccessManager(
            "Apache-Basic-Auth",
            config,
            userStore,
            groupStore);

    PasswordHandler passwordHasher = identityAccessManager.getUserManagement().getPasswordHandler();

    char[] hash =
        passwordHasher.transformPassword(
            "password1".toCharArray(),
            PasswordGenerator.generateSalt(16).getBytes(StandardCharsets.UTF_8),
            10);
    UserIdMap usernameId = identityAccessManager.getUserManagement().createUser("username", hash);

    hash =
        passwordHasher.transformPassword(
            "password2".toCharArray(),
            PasswordGenerator.generateSalt(16).getBytes(StandardCharsets.UTF_8),
            10);
    UserIdMap username2Id = identityAccessManager.getUserManagement().createUser("username2", hash);

    hash =
        passwordHasher.transformPassword(
            "password3".toCharArray(),
            PasswordGenerator.generateSalt(16).getBytes(StandardCharsets.UTF_8),
            10);
    UserIdMap fredId = identityAccessManager.getUserManagement().createUser("fred", hash);

    GroupIdMap group1IdMap = identityAccessManager.getGroupManagement().createGroup("group1");
    GroupIdMap group2IdMap = identityAccessManager.getGroupManagement().createGroup("group2");

    identityAccessManager.getGroupManagement().addUserToGroup("username", "group1");
    // identityAccessManager.addUserToGroup("username", "group2");
    identityAccessManager.getGroupManagement().addUserToGroup("username2", "group2");

    // Create the AccessControlList
    List<String> aclEntries = new ArrayList<>();
    aclEntries.add(usernameId.getAuthId() + " = Read|Write");
    aclEntries.add(username2Id.getAuthId() + " = Read|Write");
    aclEntries.add(group2IdMap.getAuthId() + " = Read|Write");
    aclEntries.add(group1IdMap.getAuthId() + " = Delete");
    aclEntries.add(fredId.getAuthId() + " = Write|Read|Delete");

    AccessControlList acl = AccessControlFactory.getInstance().get("Permission",  aclEntries);

    // Create a Subject with remote host
    Subject subjectWithRemoteHost = createSubject(usernameId);
    subjectWithRemoteHost = identityAccessManager.updateSubject(subjectWithRemoteHost);

    // Create a Subject without remote host
    Subject subjectWithoutRemoteHost = createSubject(username2Id);
    subjectWithoutRemoteHost = identityAccessManager.updateSubject(subjectWithoutRemoteHost);

    Subject subjectWithAuthDomain = createSubject(username2Id);
    subjectWithAuthDomain = identityAccessManager.updateSubject(subjectWithAuthDomain);

    long test = acl.getSubjectAccess(subjectWithRemoteHost);
    Assertions.assertTrue((test & TestPermissions.READ.getMask()) != 0);
    Assertions.assertTrue((test & TestPermissions.WRITE.getMask()) != 0);
    Assertions.assertTrue((test & TestPermissions.DELETE.getMask()) != 0);
    Assertions.assertEquals(7, test);

    // Test the ACL functionality
    Assertions.assertTrue(acl.canAccess(subjectWithAuthDomain, TestPermissions.READ.getMask()));
    Assertions.assertFalse(acl.canAccess(subjectWithAuthDomain, TestPermissions.DELETE.getMask()));

    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, TestPermissions.READ.getMask()));
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, TestPermissions.WRITE.getMask()));
    Assertions.assertFalse(acl.canAccess(subjectWithRemoteHost, TestPermissions.CREATE.getMask()));
    Assertions.assertTrue(acl.canAccess(subjectWithRemoteHost, TestPermissions.DELETE.getMask()));

    Assertions.assertTrue(acl.canAccess(subjectWithoutRemoteHost, TestPermissions.READ.getMask()));
    Assertions.assertTrue(acl.canAccess(subjectWithoutRemoteHost, TestPermissions.WRITE.getMask()));
    Assertions.assertFalse(acl.canAccess(subjectWithoutRemoteHost, TestPermissions.CREATE.getMask()));
    Assertions.assertFalse(acl.canAccess(subjectWithoutRemoteHost, TestPermissions.DELETE.getMask()));
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

    AccessControlList acl = AccessControlFactory.getInstance().get("Permission",  aclEntries);

    userMapManagement.clearAll();
    Assertions.assertEquals(0, userMapManagement.size());

    groupMapManagement.clearAll();
    Assertions.assertEquals(0, groupMapManagement.size());
  }

  @Test
  void testCanAccess_NullSubject_ReturnsFalse() {
    // Null subject
    Subject subject = null;
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new ArrayList<>());

    // Verify that the null subject is not allowed to access
    Assertions.assertFalse(acl.canAccess(subject, TestPermissions.READ.getMask()));
  }

  @Test
  void testCanAccess_NullAccess_ReturnsFalse() {
    // Create a subject with necessary principals
    Subject subject = new Subject();
    subject.getPrincipals().add(new UserPrincipal("user1"));
    subject.getPrincipals().add(new GroupPrincipal("group1"));

    // Set up the access control list with the necessary ACL entries
    List<String> aclEntries = Collections.singletonList("user1 = Read|Write");
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new ArrayList<>());


    // Verify that the subject is not allowed to access with null access
    Assertions.assertFalse(acl.canAccess(subject, 0L));
  }

  @Test
  void testCanAccess_InvalidEntry_ReturnsFalse() {
    // Create a subject with necessary principals
    Subject subject = new Subject();
    subject.getPrincipals().add(new UserPrincipal("user1"));
    subject.getPrincipals().add(new GroupPrincipal("group1"));

    // Set up the access control list with invalid ACL entry
    List<String> aclEntries = Collections.singletonList("invalidEntry");
    AccessControlList acl = AccessControlFactory.getInstance().get("Permission", new ArrayList<>());



    // Verify that the subject is not allowed to access with invalid ACL entry
    Assertions.assertFalse(acl.canAccess(subject, TestPermissions.READ.getMask()));
  }

  private Subject createSubject(UserIdMap user) {
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(user.getUsername()));
    return new Subject(false, principals, new HashSet<>(), new HashSet<>());
  }
}
