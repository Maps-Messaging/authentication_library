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

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public abstract class AbstractAuthorizationProviderTest extends BaseAuthorisationTest {



  protected AuthorizationProvider authorizationProvider;

  protected Identity identityAlice;
  private Identity identityBob;
  private Identity identityCharlie;
  private Group groupAdmins;
  private Group groupGuests;
  protected ProtectedResource protectedResource;

  private Permission readPermission;

  @BeforeEach
  void setUp() throws Exception {
    authorizationProvider = createAuthorizationProvider();

    identityAlice = AuthTestHelper.createIdentity("alice");
    identityBob = AuthTestHelper.createIdentity("bob");
    identityCharlie = AuthTestHelper.createIdentity("charlie");

    groupAdmins = AuthTestHelper.createGroup("admins");
    groupGuests = AuthTestHelper.createGroup("guests");

    protectedResource = createProtectedResource("resource-1");
    readPermission = TestPermissions.READ;

    authorizationProvider.registerIdentity(identityAlice.getId());
    authorizationProvider.registerIdentity(identityBob.getId());
    authorizationProvider.registerIdentity(identityCharlie.getId());

    authorizationProvider.registerGroup(groupAdmins.getId());
    authorizationProvider.registerGroup(groupGuests.getId());
  }

  // a) Grant access to users
  // c) Test access for users
  // e) Test denied access for users
  // g) Remove users
  @Test
  void testUserGrantAndRemovalFlow() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    assertFalse(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should not have access before grant"
    );

    authorizationProvider.grantAccess(aliceGrantee, readPermission, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should have access after grant"
    );

    assertFalse(
        authorizationProvider.canAccess(identityCharlie, readPermission, protectedResource),
        "Charlie should not have access without any grant"
    );

    authorizationProvider.revokeAccess(aliceGrantee, readPermission, protectedResource);

    assertFalse(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should not have access after revoke"
    );

    authorizationProvider.deleteIdentity(identityAlice.getId());

    assertFalse(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should not have access after identity deletion"
    );
  }

  // b) Grant access to groups
  // d) Test access for users in groups
  // f) Test denied access for users in groups
  // h) Remove users from groups
  @Test
  void testGroupGrantAndMembershipFlow() {
    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);

    addIdentityToGroup(identityBob, groupAdmins);
    assertFalse(authorizationProvider.canAccess(identityBob, readPermission, protectedResource), "Identity Bob should not have access before group grant");

    authorizationProvider.grantAccess(adminsGrantee, readPermission, protectedResource);
    assertTrue(authorizationProvider.canAccess(identityBob, readPermission, protectedResource), "Identity Bob should have access via admins group");
    assertFalse(authorizationProvider.canAccess(identityCharlie, readPermission, protectedResource), "Identity Charlie should not have access as non-member of admins");

    removeIdentityFromGroup(identityBob, groupAdmins);

    assertFalse(authorizationProvider.canAccess(identityBob, readPermission, protectedResource), "Identity Bob should not have access after being removed from admins group");

    authorizationProvider.revokeAccess(adminsGrantee, readPermission, protectedResource);

    addIdentityToGroup(identityCharlie, groupAdmins);
    assertFalse(authorizationProvider.canAccess(identityCharlie, readPermission, protectedResource), "Identity Charlie should not have access after group grant revoke");
  }

  @Test
  void testUserAndGroupGrantsDoNotInterfereIncorrectly() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);
    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);

    addIdentityToGroup(identityBob, groupAdmins);

    authorizationProvider.grantAccess(aliceGrantee, readPermission, protectedResource);
    authorizationProvider.grantAccess(adminsGrantee, readPermission, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should have direct user grant"
    );
    assertTrue(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "Bob should have access via admins group"
    );

    removeIdentityFromGroup(identityBob, groupAdmins);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should still have access via direct grant"
    );
    assertFalse(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "Bob should lose access after group membership removal"
    );
  }

  // ===== Additional permission-level behaviour tests =====

  @Test
  void testPermissionIsolationForUser() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
        "READ should be allowed after grant"
    );
    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.WRITE, protectedResource),
        "WRITE should not be allowed when only READ granted"
    );
    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.DELETE, protectedResource),
        "DELETE should not be allowed when only READ granted"
    );
    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.CREATE, protectedResource),
        "CREATE should not be allowed when only READ granted"
    );
  }

  @Test
  void testMultiplePermissionsForUser() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.WRITE, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
        "READ should be allowed after grant"
    );
    assertTrue(
        authorizationProvider.canAccess(identityAlice, TestPermissions.WRITE, protectedResource),
        "WRITE should be allowed after grant"
    );
    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.DELETE, protectedResource),
        "DELETE should not be allowed without grant"
    );
  }

  @Test
  void testRevokeSinglePermissionLeavesOthers() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.WRITE, protectedResource);

    authorizationProvider.revokeAccess(aliceGrantee, TestPermissions.WRITE, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
        "READ should still be allowed after WRITE revoke"
    );
    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.WRITE, protectedResource),
        "WRITE should be denied after revoke"
    );
  }

  // ===== Resource scoping =====

  @Test
  void testResourceScoping() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);
    ProtectedResource otherResource = createProtectedResource("resource-2");

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
        "READ should be allowed on resource-1"
    );
    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, otherResource),
        "READ should not be allowed on resource-2 without grant"
    );
  }

  // ===== Multiple groups and union semantics =====

  @Test
  void testMultipleGroupsSingleGrant() {
    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);

    addIdentityToGroup(identityBob, groupAdmins);
    addIdentityToGroup(identityBob, groupGuests);

    authorizationProvider.grantAccess(adminsGrantee, TestPermissions.READ, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityBob, TestPermissions.READ, protectedResource),
        "Bob should have READ via admins group"
    );
  }

  @Test
  void testMultipleGroupsDifferentPermissions() {
    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);
    Grantee guestsGrantee = createGranteeForGroup(groupGuests);

    addIdentityToGroup(identityBob, groupAdmins);
    addIdentityToGroup(identityBob, groupGuests);

    authorizationProvider.grantAccess(adminsGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(guestsGrantee, TestPermissions.WRITE, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityBob, TestPermissions.READ, protectedResource),
        "Bob should have READ from admins"
    );
    assertTrue(
        authorizationProvider.canAccess(identityBob, TestPermissions.WRITE, protectedResource),
        "Bob should have WRITE from guests"
    );

    removeIdentityFromGroup(identityBob, groupGuests);

    assertTrue(
        authorizationProvider.canAccess(identityBob, TestPermissions.READ, protectedResource),
        "Bob should still have READ after leaving guests"
    );
    assertFalse(
        authorizationProvider.canAccess(identityBob, TestPermissions.WRITE, protectedResource),
        "Bob should lose WRITE after leaving guests"
    );
  }

  // ===== Lifecycle / idempotency / unknown entities =====

  @Test
  void testIdempotentGrantAndRevoke() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
        "READ should be allowed after duplicate grants"
    );

    authorizationProvider.revokeAccess(aliceGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.revokeAccess(aliceGrantee, TestPermissions.READ, protectedResource);

    assertFalse(
        authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
        "READ should be denied after duplicate revokes"
    );
  }

  @Test
  void testGrantWithoutRegistrationStillProvidesAccess() {
    Identity ghost = AuthTestHelper.createIdentity("ghost");
    Grantee ghostGrantee = createGranteeForIdentity(ghost);

    // No registerIdentity(ghost) call here

    authorizationProvider.grantAccess(ghostGrantee, TestPermissions.READ, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(ghost, TestPermissions.READ, protectedResource),
        "GrantAccess should be sufficient for access; registration is not a prerequisite"
    );
  }

  @Test
  void testDeleteGroupRemovesAccess() {
    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);

    addIdentityToGroup(identityBob, groupAdmins);
    authorizationProvider.grantAccess(adminsGrantee, TestPermissions.READ, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityBob, TestPermissions.READ, protectedResource),
        "Bob should have READ via admins before deletion"
    );

    removeIdentityFromGroup(identityBob, groupAdmins);

    assertFalse(
        authorizationProvider.canAccess(identityBob, TestPermissions.READ, protectedResource),
        "Bob should not have READ after group deletion"
    );
    authorizationProvider.deleteGroup(groupAdmins.getId());

  }

  @Test
  void testDenyOverridesUserGrant() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    // Baseline: no access
    assertFalse(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should not have access before grant"
    );

    // Grant then deny
    authorizationProvider.grantAccess(aliceGrantee, readPermission, protectedResource);
    assertTrue(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should have access after grant"
    );

    authorizationProvider.denyAccess(aliceGrantee, readPermission, protectedResource);

    assertFalse(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Alice should be denied after explicit deny, even with existing grant"
    );
  }

  @Test
  void testDenyWithoutGrantStillDenies() {
    Identity ghost = AuthTestHelper.createIdentity("ghost");
    Grantee ghostGrantee = createGranteeForIdentity(ghost);

    // No registration, no grant, just deny
    authorizationProvider.denyAccess(ghostGrantee, readPermission, protectedResource);

    assertFalse(
        authorizationProvider.canAccess(ghost, readPermission, protectedResource),
        "Explicit deny must block access even without prior grant or registration"
    );
  }

  @Test
  void testUserDenyOverridesGroupGrant() {
    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);
    Grantee bobGrantee = createGranteeForIdentity(identityBob);

    addIdentityToGroup(identityBob, groupAdmins);

    // Group grant gives Bob access
    authorizationProvider.grantAccess(adminsGrantee, readPermission, protectedResource);
    assertTrue(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "Bob should have READ via admins group before deny"
    );

    // Explicit user-level deny must override group grant
    authorizationProvider.denyAccess(bobGrantee, readPermission, protectedResource);

    assertFalse(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "User-level deny should override group grant"
    );

    // Even if he leaves the group, still denied until policy is cleaned up
    removeIdentityFromGroup(identityBob, groupAdmins);
    assertFalse(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "Bob should remain denied after leaving group unless deny is revoked"
    );
  }


  // ===== Helpers for membership sync in tests =====

  private void addIdentityToGroup(Identity identity, Group group) {
    authorizationProvider.addGroupMember(group.getId(), identity.getId());
    identity.getGroupList().add(group);
  }

  private void removeIdentityFromGroup(Identity identity, Group group) {
    authorizationProvider.removeGroupMember(group.getId(), identity.getId());
    identity.getGroupList().remove(group);
  }

  // ===== Abstract hooks for concrete implementations =====

  protected abstract AuthorizationProvider createAuthorizationProvider() throws Exception;

}
