/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.authorisation.impl.caching;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import io.mapsmessaging.security.identity.GroupEntry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class CachingAuthorizationProviderCoverageTest {

  private static final Permission READ = new Permission() {
    @Override public String getName() { return "READ"; }
    @Override public String getDescription() { return "read"; }
    @Override public long getMask() { return 1; }
  };

  @Test
  void cachesDelegateDecisionUntilExpiry() {
    MutableClock clock = new MutableClock(Instant.parse("2026-09-29T00:00:00Z"));
    StubProvider delegate = new StubProvider();
    ExecutorService executor = Executors.newSingleThreadExecutor();
    CachingAuthorizationProvider provider =
        new CachingAuthorizationProvider(
            delegate, Duration.ofSeconds(10), Duration.ZERO, executor, clock);
    try {
      Identity identity = identity();
      ProtectedResource resource = resource();

      delegate.allowed = true;
      assertTrue(provider.canAccess(identity, READ, resource));
      assertEquals(1, delegate.canAccessCalls);

      delegate.allowed = false;
      assertTrue(provider.canAccess(identity, READ, resource));
      assertEquals(1, delegate.canAccessCalls);

      clock.advance(Duration.ofSeconds(11));
      assertFalse(provider.canAccess(identity, READ, resource));
      assertEquals(2, delegate.canAccessCalls);
    } finally {
      provider.shutdown();
    }
  }

  @Test
  void coversBulkChecksAndDelegatedSurface() {
    StubProvider delegate = new StubProvider();
    CachingAuthorizationProvider provider =
        new CachingAuthorizationProvider(delegate, Duration.ofSeconds(30));
    try {
      Identity identity = identity();
      Group group = group();
      ProtectedResource resource = resource();
      AuthRequest request = new AuthRequest(identity, READ, resource);
      Grantee user = Grantee.forIdentity(identity);
      UUID identityId = identity.getId();
      UUID groupId = group.getId();
      ResourceCreationContext creation =
          new ResourceCreationContext(identity, null, ResourceInitialGrantPolicy.NONE);

      assertEquals("Caching", provider.getName());
      assertSame(delegate, provider.getDelegate());
      assertNull(provider.create(new ConfigurationProperties(), new Permission[]{READ}, null));

      delegate.allowed = true;
      assertTrue(provider.hasAllAccess(new AuthRequest[]{request}));
      assertTrue(provider.hasOneAccess(new AuthRequest[]{request}));

      provider.reset();
      assertEquals(1, delegate.resetCalls);

      AccessDecision decision = new AccessDecision();
      delegate.accessDecision = decision;
      assertSame(decision, provider.explainAccess(identity, READ, resource));

      EffectiveAccess effectiveAccess = new EffectiveAccess();
      delegate.effectiveAccess = effectiveAccess;
      assertSame(effectiveAccess, provider.explainEffectiveAccess(identity, resource));

      provider.grantAccess(user, READ, resource);
      provider.denyAccess(user, READ, resource);
      provider.revokeAccess(user, READ, resource);
      provider.registerIdentity(identityId);
      provider.deleteIdentity(identityId);
      provider.registerGroup(groupId);
      provider.deleteGroup(groupId);
      provider.addGroupMember(groupId, identityId);
      provider.removeGroupMember(groupId, identityId);
      provider.registerResource(resource, creation);
      provider.deleteResource(resource);

      assertEquals(1, delegate.grantCalls);
      assertEquals(1, delegate.denyCalls);
      assertEquals(1, delegate.revokeCalls);
      assertEquals(1, delegate.registerIdentityCalls);
      assertEquals(1, delegate.deleteIdentityCalls);
      assertEquals(1, delegate.registerGroupCalls);
      assertEquals(1, delegate.deleteGroupCalls);
      assertEquals(1, delegate.addGroupMemberCalls);
      assertEquals(1, delegate.removeGroupMemberCalls);
      assertEquals(1, delegate.registerResourceCalls);
      assertEquals(1, delegate.deleteResourceCalls);

      delegate.identityGrants = List.of();
      delegate.groupGrants = List.of();
      delegate.resourceGrants = List.of();
      assertSame(delegate.identityGrants, provider.getGrantsForIdentity(identity));
      assertSame(delegate.groupGrants, provider.getGrantsForGroup(group));
      assertSame(delegate.resourceGrants, provider.getGrantsForResource(resource));

      delegate.allowed = false;
      provider.reset();
      assertFalse(provider.hasAllAccess(new AuthRequest[]{request}));
      assertFalse(provider.hasOneAccess(new AuthRequest[]{request}));
    } finally {
      provider.shutdown();
    }
  }

  @Test
  void validatesRequiredConstructorArgumentsAndDefaults() {
    StubProvider delegate = new StubProvider();
    assertThrows(
        NullPointerException.class,
        () -> new CachingAuthorizationProvider(null, Duration.ofSeconds(1)));
    assertThrows(
        NullPointerException.class,
        () -> new CachingAuthorizationProvider(
            delegate,
            Duration.ofSeconds(1),
            Duration.ZERO,
            null,
            null));

    CachingAuthorizationProvider provider =
        new CachingAuthorizationProvider(delegate, null, null);
    provider.shutdown();
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

  private static final class MutableClock extends Clock {
    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    void advance(Duration duration) {
      instant = instant.plus(duration);
    }

    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    @Override public Instant instant() { return instant; }
  }

  private static final class StubProvider implements AuthorizationProvider {
    private boolean allowed;
    private int canAccessCalls;
    private int resetCalls;
    private int grantCalls;
    private int denyCalls;
    private int revokeCalls;
    private int registerIdentityCalls;
    private int deleteIdentityCalls;
    private int registerGroupCalls;
    private int deleteGroupCalls;
    private int addGroupMemberCalls;
    private int removeGroupMemberCalls;
    private int registerResourceCalls;
    private int deleteResourceCalls;
    private AccessDecision accessDecision;
    private EffectiveAccess effectiveAccess;
    private Collection<Grant> identityGrants;
    private Collection<Grant> groupGrants;
    private Collection<Grant> resourceGrants;

    @Override public String getName() { return "stub"; }
    @Override public AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions, ResourceTraversalFactory factory) { return this; }
    @Override public void reset() { resetCalls++; }
    @Override public boolean canAccess(Identity identity, Permission permission, ProtectedResource protectedResource) {
      canAccessCalls++;
      return allowed;
    }
    @Override public boolean hasAllAccess(AuthRequest[] requests) { return false; }
    @Override public boolean hasOneAccess(AuthRequest[] requests) { return false; }
    @Override public AccessDecision explainAccess(Identity identity, Permission permission, ProtectedResource protectedResource) { return accessDecision; }
    @Override public EffectiveAccess explainEffectiveAccess(Identity identity, ProtectedResource protectedResource) { return effectiveAccess; }
    @Override public void grantAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) { grantCalls++; }
    @Override public void denyAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) { denyCalls++; }
    @Override public void revokeAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) { revokeCalls++; }
    @Override public void registerIdentity(UUID identityId) { registerIdentityCalls++; }
    @Override public void deleteIdentity(UUID identityId) { deleteIdentityCalls++; }
    @Override public void registerGroup(UUID groupId) { registerGroupCalls++; }
    @Override public void deleteGroup(UUID groupId) { deleteGroupCalls++; }
    @Override public void addGroupMember(UUID groupId, UUID identityId) { addGroupMemberCalls++; }
    @Override public void removeGroupMember(UUID groupId, UUID identityId) { removeGroupMemberCalls++; }
    @Override public void registerResource(ProtectedResource protectedResource, ResourceCreationContext context) { registerResourceCalls++; }
    @Override public void deleteResource(ProtectedResource protectedResource) { deleteResourceCalls++; }
    @Override public Collection<Grant> getGrantsForIdentity(Identity identity) { return identityGrants; }
    @Override public Collection<Grant> getGrantsForGroup(Group group) { return groupGrants; }
    @Override public Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) { return resourceGrants; }
  }
}
