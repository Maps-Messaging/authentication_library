/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.authorisation.impl.acl;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import io.mapsmessaging.security.identity.GroupEntry;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AclAuthorizationProviderCoverageTest {

  private static final Permission READ = permission("READ", 1L);
  private static final Permission WRITE = permission("WRITE", 2L);
  private static final Permission[] PERMISSIONS = {READ, WRITE};

  @Test
  void coversGrantDenyRevokeAndIntrospection() {
    ProtectedResource resource = new ProtectedResource("topic", "demo/test", "tenant");
    AclAuthorizationProvider provider =
        new AclAuthorizationProvider("", PERMISSIONS, null, singleResourceFactory());

    Identity alice = identity("alice", List.of());
    Grantee aliceGrantee = Grantee.forIdentity(alice);

    assertEquals("ACL", provider.getName());
    assertFalse(provider.canAccess(alice, READ, resource));

    provider.grantAccess(aliceGrantee, READ, resource);
    assertTrue(provider.canAccess(alice, READ, resource));
    assertFalse(provider.canAccess(alice, WRITE, resource));

    AccessDecision allowDecision = provider.explainAccess(alice, READ, resource);
    assertTrue(allowDecision.isAllowed());
    assertEquals(DecisionReason.ALLOW_EXPLICIT_IDENTITY, allowDecision.getDecisionReason());
    assertEquals(1, allowDecision.getContributingGrants().size());

    provider.denyAccess(aliceGrantee, WRITE, resource);
    AccessDecision denyDecision = provider.explainAccess(alice, WRITE, resource);
    assertFalse(denyDecision.isAllowed());
    assertEquals(DecisionReason.DENY_EXPLICIT_IDENTITY, denyDecision.getDecisionReason());

    assertTrue(provider.hasAllAccess(new AuthRequest[]{new AuthRequest(alice, READ, resource)}));
    assertFalse(provider.hasAllAccess(new AuthRequest[]{
        new AuthRequest(alice, READ, resource),
        new AuthRequest(alice, WRITE, resource)}));
    assertTrue(provider.hasOneAccess(new AuthRequest[]{
        new AuthRequest(alice, WRITE, resource),
        new AuthRequest(alice, READ, resource)}));
    assertFalse(provider.hasOneAccess(new AuthRequest[]{new AuthRequest(alice, WRITE, resource)}));

    assertFalse(provider.getGrantsForIdentity(alice).isEmpty());
    assertFalse(provider.getGrantsForResource(resource).isEmpty());

    EffectiveAccess effective = provider.explainEffectiveAccess(alice, resource);
    assertTrue(effective.getAllowedPermissions().contains(READ));
    assertTrue(effective.getDeniedPermissions().contains(WRITE));
    assertEquals(2, effective.getDecisionsByPermission().size());

    provider.revokeAccess(aliceGrantee, READ, resource);
    assertFalse(provider.canAccess(alice, READ, resource));

    provider.revokeAccess(aliceGrantee, READ, new ProtectedResource("topic", "missing", "tenant"));
  }

  @Test
  void coversGroupDecisionsAndLifecycleOperations() {
    ProtectedResource resource = new ProtectedResource("topic", "demo/group", null);
    AclAuthorizationProvider provider =
        new AclAuthorizationProvider("", PERMISSIONS, null, singleResourceFactory());

    Group group = group("operators");
    Identity alice = identity("alice", List.of(group));
    Grantee groupGrantee = Grantee.forGroup(group);

    provider.grantAccess(groupGrantee, READ, resource);
    assertTrue(provider.canAccess(alice, READ, resource));

    AccessDecision decision = provider.explainAccess(alice, READ, resource);
    assertTrue(decision.isAllowed());
    assertEquals(DecisionReason.ALLOW_EXPLICIT_GROUP, decision.getDecisionReason());
    assertEquals(1, decision.getContributingGroups().size());

    assertFalse(provider.getGrantsForGroup(group).isEmpty());

    provider.deleteGroup(group.getId());
    assertFalse(provider.canAccess(alice, READ, resource));

    provider.grantAccess(Grantee.forIdentity(alice), READ, resource);
    provider.deleteIdentity(alice.getId());
    assertFalse(provider.canAccess(alice, READ, resource));

    provider.registerIdentity(alice.getId());
    provider.registerGroup(group.getId());
    provider.addGroupMember(group.getId(), alice.getId());
    provider.removeGroupMember(group.getId(), alice.getId());

    provider.registerResource(
        resource,
        new ResourceCreationContext(alice, null, ResourceInitialGrantPolicy.NONE));
    provider.deleteResource(resource);
    assertTrue(provider.getGrantsForResource(resource).isEmpty());
  }

  @Test
  void coversBatchResetAndDefaultDecision() {
    ProtectedResource resource = new ProtectedResource("topic", "none", null);
    AclAuthorizationProvider provider =
        new AclAuthorizationProvider("", PERMISSIONS, null, singleResourceFactory());
    Identity alice = identity("alice", List.of());

    AccessDecision decision = provider.explainAccess(alice, READ, resource);
    assertFalse(decision.isAllowed());
    assertEquals(DecisionReason.DEFAULT_DENY, decision.getDecisionReason());

    assertDoesNotThrow(() -> {
      provider.startBatch(1000);
      provider.grantAccess(Grantee.forIdentity(alice), READ, resource);
      provider.stopBatch();
      provider.reset();
    });
    assertFalse(provider.canAccess(alice, READ, resource));
  }

  private static Permission permission(String name, long mask) {
    return new Permission() {
      @Override public String getName() { return name; }
      @Override public String getDescription() { return name.toLowerCase(); }
      @Override public long getMask() { return mask; }
    };
  }

  private static Identity identity(String name, List<Group> groups) {
    return new Identity(UUID.randomUUID(), name, Map.of(), groups);
  }

  private static Group group(String name) {
    return new Group(UUID.randomUUID(), new GroupEntry(name, new TreeSet<>()));
  }

  private static ResourceTraversalFactory singleResourceFactory() {
    return new ResourceTraversalFactory() {
      @Override
      public ResourceTraversal create(ProtectedResource protectedResource) {
        return new ResourceTraversal() {
          private boolean available = true;

          @Override public boolean hasMore() { return available; }
          @Override public ProtectedResource current() { return protectedResource; }
          @Override public void moveToParent() { available = false; }
        };
      }
    };
  }
}
