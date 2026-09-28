/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.authorisation.impl.open;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import io.mapsmessaging.security.identity.GroupEntry;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class OpenAuthorizationProviderCoverageTest {

  @Test
  void openProviderAllowsEverythingAndMaintainsNoState() throws Exception {
    OpenAuthorizationProvider provider = new OpenAuthorizationProvider();
    Permission permission = new Permission() {
      @Override public String getName() { return "READ"; }
      @Override public String getDescription() { return "read"; }
      @Override public long getMask() { return 1; }
    };
    Identity identity = new Identity(UUID.randomUUID(), "alice", Map.of(), List.of());
    Group group = new Group(UUID.randomUUID(), new GroupEntry("operators", new TreeSet<>()));
    ProtectedResource resource = new ProtectedResource("topic", "demo/test", null);
    Grantee grantee = Grantee.forIdentity(identity);
    ResourceCreationContext context =
        new ResourceCreationContext(identity, null, ResourceInitialGrantPolicy.NONE);

    assertEquals("Open", provider.getName());
    assertSame(provider, provider.create(new ConfigurationProperties(), new Permission[]{permission}, null));
    assertTrue(provider.canAccess(identity, permission, resource));
    assertTrue(provider.hasAllAccess(new AuthRequest[0]));
    assertTrue(provider.hasOneAccess(new AuthRequest[0]));

    assertDoesNotThrow(provider::reset);
    assertDoesNotThrow(() -> provider.grantAccess(grantee, permission, resource));
    assertDoesNotThrow(() -> provider.denyAccess(grantee, permission, resource));
    assertDoesNotThrow(() -> provider.revokeAccess(grantee, permission, resource));
    assertDoesNotThrow(() -> provider.registerIdentity(identity.getId()));
    assertDoesNotThrow(() -> provider.deleteIdentity(identity.getId()));
    assertDoesNotThrow(() -> provider.registerGroup(group.getId()));
    assertDoesNotThrow(() -> provider.deleteGroup(group.getId()));
    assertDoesNotThrow(() -> provider.addGroupMember(group.getId(), identity.getId()));
    assertDoesNotThrow(() -> provider.removeGroupMember(group.getId(), identity.getId()));
    assertDoesNotThrow(() -> provider.registerResource(resource, context));
    assertDoesNotThrow(() -> provider.deleteResource(resource));

    assertTrue(provider.getGrantsForIdentity(identity).isEmpty());
    assertTrue(provider.getGrantsForGroup(group).isEmpty());
    assertTrue(provider.getGrantsForResource(resource).isEmpty());
  }
}
