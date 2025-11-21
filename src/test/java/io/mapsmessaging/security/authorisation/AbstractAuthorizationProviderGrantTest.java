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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import java.util.Collection;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public abstract class AbstractAuthorizationProviderGrantTest extends BaseAuthorisationTest {


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

    identityAlice = createIdentity("alice");
    identityBob = createIdentity("bob");
    identityCharlie = createIdentity("charlie");

    groupAdmins = createGroup("admins");
    groupGuests = createGroup("guests");

    protectedResource = createProtectedResource("resource-1");
    readPermission = TestPermissions.READ;

    authorizationProvider.registerIdentity(identityAlice.getId());
    authorizationProvider.registerIdentity(identityBob.getId());
    authorizationProvider.registerIdentity(identityCharlie.getId());

    authorizationProvider.registerGroup(groupAdmins.getId());
    authorizationProvider.registerGroup(groupGuests.getId());
  }

  @Test
  void testGetGrantsForIdentityReturnsDirectGrants() {
    Identity identity = identityAlice;
    Grantee aliceGrantee = createGranteeForIdentity(identity);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.WRITE, protectedResource);

    Collection<Grant> grants = authorizationProvider.getGrantsForIdentity(identity);

    assertNotNull(grants, "Grants for identity should not be null");

    assertTrue(
        grants.stream().anyMatch(g ->
            g.getGrantee().type() == GranteeType.USER
                && g.getGrantee().id().equals(identity.getId())
                && g.getPermission() == TestPermissions.READ
                && resourceMatches(g.getProtectedResource(), protectedResource)
        ),
        "READ grant for identity should be present"
    );

    assertTrue(
        grants.stream().anyMatch(g ->
            g.getGrantee().type() == GranteeType.USER
                && g.getGrantee().id().equals(identity.getId())
                && g.getPermission() == TestPermissions.WRITE
                && resourceMatches(g.getProtectedResource(), protectedResource)
        ),
        "WRITE grant for identity should be present"
    );
  }

  @Test
  void testGetGrantsForGroupReturnsGroupGrants() {
    Group group = createGroup("introspection-admins");
    authorizationProvider.registerGroup(group.getId());

    Grantee groupGrantee = createGranteeForGroup(group);

    authorizationProvider.grantAccess(groupGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(groupGrantee, TestPermissions.DELETE, protectedResource);

    Collection<Grant> grants = authorizationProvider.getGrantsForGroup(group);

    assertNotNull(grants, "Grants for group should not be null");

    assertTrue(
        grants.stream().anyMatch(g ->
            g.getGrantee().type() == GranteeType.GROUP
                && g.getGrantee().id().equals(group.getId())
                && g.getPermission() == TestPermissions.READ
                && resourceMatches(g.getProtectedResource(), protectedResource)
        ),
        "READ grant for group should be present"
    );

    assertTrue(
        grants.stream().anyMatch(g ->
            g.getGrantee().type() == GranteeType.GROUP
                && g.getGrantee().id().equals(group.getId())
                && g.getPermission() == TestPermissions.DELETE
                && resourceMatches(g.getProtectedResource(), protectedResource)
        ),
        "DELETE grant for group should be present"
    );
  }

  @Test
  void testGetGrantsForResourceReturnsAllGrantsOnResource() {
    Identity identity = identityAlice;
    Group group = createGroup("introspection-resource-group");
    authorizationProvider.registerGroup(group.getId());

    Grantee userGrantee = createGranteeForIdentity(identity);
    Grantee groupGrantee = createGranteeForGroup(group);

    authorizationProvider.grantAccess(userGrantee, TestPermissions.READ, protectedResource);
    authorizationProvider.grantAccess(groupGrantee, TestPermissions.WRITE, protectedResource);

    Collection<Grant> grants = authorizationProvider.getGrantsForResource(protectedResource);

    assertNotNull(grants, "Grants for resource should not be null");

    assertTrue(
        grants.stream().anyMatch(g ->
            g.getGrantee().type() == GranteeType.USER
                && g.getGrantee().id().equals(identity.getId())
                && g.getPermission() == TestPermissions.READ
                && resourceMatches(g.getProtectedResource(), protectedResource)
        ),
        "READ grant for user on resource should be present"
    );

    assertTrue(
        grants.stream().anyMatch(g ->
            g.getGrantee().type() == GranteeType.GROUP
                && g.getGrantee().id().equals(group.getId())
                && g.getPermission() == TestPermissions.WRITE
                && resourceMatches(g.getProtectedResource(), protectedResource)
        ),
        "WRITE grant for group on resource should be present"
    );
  }

  @Test
  void testGetGrantsForIdentityEmptyWhenNoGrants() {
    Identity identity = createIdentity("introspection-no-grants-user");

    Collection<Grant> grants = authorizationProvider.getGrantsForIdentity(identity);

    assertNotNull(grants, "Grants collection should not be null");
    assertTrue(grants.isEmpty(), "Grants for identity without any grant should be empty");
  }

  @Test
  void testGetGrantsForGroupEmptyWhenNoGrants() {
    Group group = createGroup("introspection-no-grants-group");
    authorizationProvider.registerGroup(group.getId());

    Collection<Grant> grants = authorizationProvider.getGrantsForGroup(group);

    assertNotNull(grants, "Grants collection should not be null");
    assertTrue(grants.isEmpty(), "Grants for group without any grant should be empty");
  }

  @Test
  void testGetGrantsForResourceEmptyWhenNoGrants() {
    ProtectedResource newResource = createProtectedResource("isolated-resource-" + UUID.randomUUID());

    Collection<Grant> grants = authorizationProvider.getGrantsForResource(newResource);

    assertNotNull(grants, "Grants collection should not be null");
    assertTrue(grants.isEmpty(), "Grants for resource without any grant should be empty");
  }

  private boolean resourceMatches(ProtectedResource left, ProtectedResource right) {
    if (left == null || right == null) {
      return false;
    }
    return Objects.equals(left.getResourceType(), right.getResourceType())
        && Objects.equals(left.getResourceId(), right.getResourceId())
        && Objects.equals(left.getTenant(), right.getTenant());
  }

  protected abstract AuthorizationProvider createAuthorizationProvider() throws Exception;
}
