/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.authorisation;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.Identity;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ResourceCreationContextCoverageTest {

  @Test
  void exposesCreationContextValues() {
    Identity owner = new Identity(UUID.randomUUID(), "owner", Map.of(), List.of());
    ProtectedResource parent = new ProtectedResource("namespace", "parent", "tenant");

    ResourceCreationContext context =
        new ResourceCreationContext(
            owner,
            parent,
            ResourceInitialGrantPolicy.OWNER_FULL);

    assertSame(owner, context.getOwnerIdentity());
    assertSame(parent, context.getParentProtectedResource());
    assertEquals(ResourceInitialGrantPolicy.OWNER_FULL, context.getInitialGrantPolicy());
  }

  @Test
  void enumValuesRemainCompleteAndResolvable() {
    assertArrayEquals(
        new ResourceInitialGrantPolicy[] {
            ResourceInitialGrantPolicy.NONE,
            ResourceInitialGrantPolicy.OWNER_MANAGE,
            ResourceInitialGrantPolicy.OWNER_FULL,
            ResourceInitialGrantPolicy.INHERIT_FROM_PARENT
        },
        ResourceInitialGrantPolicy.values());

    assertEquals(
        ResourceInitialGrantPolicy.OWNER_MANAGE,
        ResourceInitialGrantPolicy.valueOf("OWNER_MANAGE"));

    assertEquals(8, DecisionReason.values().length);
    assertEquals(
        DecisionReason.DEFAULT_DENY,
        DecisionReason.valueOf("DEFAULT_DENY"));
  }
}
