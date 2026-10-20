/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.authorisation;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.identity.GroupEntry;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthorizationProviderCoverageTest {

  private static final Permission PERMISSION = new Permission() {
    @Override public String getName() { return "READ"; }
    @Override public String getDescription() { return "read"; }
    @Override public long getMask() { return 1; }
  };

  @Test
  void defaultUnsupportedOperationsThrow() {
    StubProvider provider = new StubProvider();
    Identity identity = identity();
    Group group = group();
    ProtectedResource resource = resource();

    assertThrows(UnsupportedOperationException.class,
        () -> provider.explainAccess(identity, PERMISSION, resource));
    assertThrows(UnsupportedOperationException.class,
        () -> provider.explainEffectiveAccess(identity, resource));
    assertThrows(UnsupportedOperationException.class,
        () -> provider.getGrantsForIdentity(identity));
    assertThrows(UnsupportedOperationException.class,
        () -> provider.getGrantsForGroup(group));
    assertThrows(UnsupportedOperationException.class,
        () -> provider.getGrantsForResource(resource));
  }

  @Test
  void defaultLifecycleMethodsAreNoOps() {
    StubProvider provider = new StubProvider();
    UUID identityId = UUID.randomUUID();
    UUID groupId = UUID.randomUUID();

    assertDoesNotThrow(() -> {
      provider.registerIdentity(identityId);
      provider.deleteIdentity(identityId);
      provider.registerGroup(groupId);
      provider.deleteGroup(groupId);
      provider.addGroupMember(groupId, identityId);
      provider.removeGroupMember(groupId, identityId);
      provider.setGroupsForIdentity(identityId, List.of(groupId));
      provider.registerResource(resource(),
          new ResourceCreationContext(identity(), null, ResourceInitialGrantPolicy.NONE));
      provider.deleteResource(resource());
      provider.startBatch(1000);
      provider.stopBatch();
    });
  }

  @Test
  void convenienceGrantAndRevokeMethodsBuildCorrectGrantees() {
    StubProvider provider = new StubProvider();
    Identity identity = identity();
    Group group = group();
    ProtectedResource resource = resource();

    provider.grant(identity, PERMISSION, resource);
    assertEquals(GranteeType.USER, provider.lastGrantee.type());
    assertEquals(identity.getId(), provider.lastGrantee.id());
    assertSame(PERMISSION, provider.lastPermission);
    assertSame(resource, provider.lastResource);

    provider.grant(group, PERMISSION, resource);
    assertEquals(GranteeType.GROUP, provider.lastGrantee.type());
    assertEquals(group.getId(), provider.lastGrantee.id());

    provider.revoke(identity, PERMISSION, resource);
    assertEquals(GranteeType.USER, provider.lastGrantee.type());

    provider.revoke(group, PERMISSION, resource);
    assertEquals(GranteeType.GROUP, provider.lastGrantee.type());
  }

  private static Identity identity() {
    return new Identity(UUID.randomUUID(), "alice", Map.of(), List.of());
  }

  private static Group group() {
    return new Group(UUID.randomUUID(), new GroupEntry("operators", new TreeSet<>()));
  }

  private static ProtectedResource resource() {
    return new ProtectedResource("topic", "demo/test", "tenant");
  }

  private static final class StubProvider implements AuthorizationProvider {
    private Grantee lastGrantee;
    private Permission lastPermission;
    private ProtectedResource lastResource;

    @Override public String getName() { return "stub"; }
    @Override public AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions, ResourceTraversalFactory factory) { return this; }
    @Override public void reset() {}
    @Override public boolean canAccess(Identity identity, Permission permission, ProtectedResource protectedResource) { return false; }
    @Override public boolean hasAllAccess(AuthRequest[] requests) { return false; }
    @Override public boolean hasOneAccess(AuthRequest[] requests) { return false; }

    @Override
    public void grantAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) {
      lastGrantee = grantee;
      lastPermission = permission;
      lastResource = protectedResource;
    }

    @Override
    public void revokeAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) {
      lastGrantee = grantee;
      lastPermission = permission;
      lastResource = protectedResource;
    }
  }
}
