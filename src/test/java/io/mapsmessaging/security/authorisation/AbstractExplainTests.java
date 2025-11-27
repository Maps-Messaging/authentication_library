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

import static com.auth0.utils.Asserts.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public abstract class AbstractExplainTests extends BaseAuthorisationTest {



  protected AuthorizationProvider authorizationProvider;

  protected Identity identityAlice;
  private Identity identityBob;
  private Group groupAdmins;
  protected ProtectedResource protectedResource;

  private Permission readPermission;

  @BeforeEach
  void configure() throws Exception {
    authorizationProvider = createAuthorizationProvider();

    identityAlice = AuthTestHelper.createIdentity("alice");
    identityBob = AuthTestHelper.createIdentity("bob");

    groupAdmins = AuthTestHelper.createGroup("admins");

    protectedResource = createProtectedResource("resource-1");
    readPermission = TestPermissions.READ;

    authorizationProvider.registerIdentity(identityAlice.getId());
    authorizationProvider.registerIdentity(identityBob.getId());

    authorizationProvider.registerGroup(groupAdmins.getId());
  }

  @Test
  void testExplainAccessForUserGrant() {
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


    AccessDecision decision =
        authorizationProvider.explainAccess(identityAlice, readPermission, protectedResource);

    assertNotNull(decision, "AccessDecision must not be null");
    assertTrue(decision.isAllowed(), "Decision should report allowed");
    assertEquals(
        DecisionReason.ALLOW_EXPLICIT_IDENTITY,
        decision.getDecisionReason(),
        "Reason should be explicit identity allow on this resource"
    );
    assertNotNull(decision.getIdentity(), "Decision must carry identity");
    assertEquals(identityAlice.getId(), decision.getIdentity().getId(), "Identity IDs should match");
    assertEquals(readPermission.getName(), decision.getPermission().getName(), "Permission names should match");
  }

  @Test
  void testExplainAccessDefaultDeny() {
    // No grants at all
    assertFalse(
        authorizationProvider.canAccess(identityAlice, readPermission, protectedResource),
        "Precondition: Alice must not have access without grants"
    );

    AccessDecision decision =
        authorizationProvider.explainAccess(identityAlice, readPermission, protectedResource);

    assertNotNull(decision, "AccessDecision must not be null");
    assertFalse(decision.isAllowed(), "Decision should report denied");
    assertEquals(
        DecisionReason.DEFAULT_DENY,
        decision.getDecisionReason(),
        "Reason should be default deny when no policy matches"
    );
  }

  @Test
  void testExplainAccessUserDenyOverridesGroupGrant() {
    addIdentityToGroup(identityBob, groupAdmins);

    Grantee adminsGrantee = createGranteeForGroup(groupAdmins);
    Grantee bobGrantee = createGranteeForIdentity(identityBob);

    authorizationProvider.grantAccess(adminsGrantee, readPermission, protectedResource);

    assertTrue(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "Precondition: Bob must have access via group grant"
    );

    authorizationProvider.denyAccess(bobGrantee, readPermission, protectedResource);

    assertFalse(
        authorizationProvider.canAccess(identityBob, readPermission, protectedResource),
        "Precondition: Bob must be denied after explicit user deny"
    );

    AccessDecision decision =
        authorizationProvider.explainAccess(identityBob, readPermission, protectedResource);

    assertNotNull(decision, "AccessDecision must not be null");
    assertFalse(decision.isAllowed(), "Decision should report denied");
    assertEquals(
        DecisionReason.DENY_EXPLICIT_IDENTITY,
        decision.getDecisionReason(),
        "User-level deny should be reported as explicit identity deny"
    );
  }

  @Test
  void testExplainEffectiveAccessAggregatesPermissions() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.WRITE, protectedResource);

    EffectiveAccess effectiveAccess =
        authorizationProvider.explainEffectiveAccess(identityAlice, protectedResource);

    assertNotNull(effectiveAccess, "EffectiveAccess must not be null");
    assertEquals(identityAlice.getId(), effectiveAccess.getIdentity().getId(), "Identity IDs should match");
    assertEquals(protectedResource, effectiveAccess.getProtectedResource(), "ProtectedResource should match");

    assertTrue(
        effectiveAccess.getAllowedPermissions().contains(TestPermissions.READ),
        "READ must be in allowed permissions"
    );
    assertTrue(
        effectiveAccess.getAllowedPermissions().contains(TestPermissions.WRITE),
        "WRITE must be in allowed permissions"
    );

    AccessDecision readDecision =
        effectiveAccess.getDecisionsByPermission().get(TestPermissions.READ);
    assertNotNull(readDecision, "EffectiveAccess must contain a decision for READ");
    assertTrue(readDecision.isAllowed(), "READ decision should be allowed");
    assertEquals(
        DecisionReason.ALLOW_EXPLICIT_IDENTITY,
        readDecision.getDecisionReason(),
        "READ decision reason should be explicit identity allow"
    );

    AccessDecision writeDecision =
        effectiveAccess.getDecisionsByPermission().get(TestPermissions.WRITE);
    assertNotNull(writeDecision, "EffectiveAccess must contain a decision for WRITE");
    assertTrue(writeDecision.isAllowed(), "WRITE decision should be allowed");
  }


  protected abstract AuthorizationProvider createAuthorizationProvider() throws Exception;

  private void addIdentityToGroup(Identity identity, Group group) {
    authorizationProvider.addGroupMember(group.getId(), identity.getId());
    identity.getGroupList().add(group);
  }

}
