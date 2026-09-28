/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.authorisation.impl.acl;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.Access;
import io.mapsmessaging.security.identity.GroupEntry;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AccessControlListCoverageTest {

  private static final long READ = 1L;
  private static final long WRITE = 2L;

  @Test
  void identityEntriesAllowDenyAndRemoveAccess() {
    AccessControlList acl = new AccessControlList();
    UUID userId = UUID.randomUUID();
    Identity identity = identity(userId, List.of());

    assertEquals(Access.UNKNOWN, acl.canAccess(identity, READ));
    assertEquals(Access.UNKNOWN, acl.evaluateAccess(identity, READ).getAccess());
    assertEquals(0L, acl.getSubjectAccess(identity));
    assertEquals(0L, acl.getRawAccess(userId));

    assertTrue(acl.addUser(userId, READ, true));
    assertEquals(Access.ALLOW, acl.canAccess(identity, READ));
    AclAccessResult allow = acl.evaluateAccess(identity, READ);
    assertEquals(Access.ALLOW, allow.getAccess());
    assertEquals(userId, allow.getDecidingAuthId());
    assertFalse(allow.isGroupDecision());
    assertEquals(READ, acl.getSubjectAccess(identity));

    assertTrue(acl.addUser(userId, WRITE, false));
    assertEquals(Access.DENY, acl.canAccess(identity, WRITE));
    assertEquals(READ, acl.getRawAccess(userId));

    assertTrue(acl.remove(userId, READ));
    assertEquals(Access.UNKNOWN, acl.canAccess(identity, READ));
    assertTrue(acl.remove(userId, -1L));
    assertFalse(acl.remove(userId, -1L));
    assertTrue(acl.getAclEntries().isEmpty());
  }

  @Test
  void groupEntriesParticipateWhenIdentityHasNoDecision() {
    AccessControlList acl = new AccessControlList();
    UUID groupId = UUID.randomUUID();
    Group group = group(groupId, "operators");
    Identity identity = identity(UUID.randomUUID(), List.of(group));

    assertTrue(acl.addGroup(groupId, READ, true));
    assertEquals(READ, acl.getGroupAccess(group));
    assertEquals(READ, acl.getSubjectAccess(identity));
    assertEquals(Access.ALLOW, acl.canAccess(identity, READ));

    AclAccessResult result = acl.evaluateAccess(identity, READ);
    assertEquals(Access.ALLOW, result.getAccess());
    assertEquals(groupId, result.getDecidingAuthId());
    assertTrue(result.isGroupDecision());

    assertTrue(acl.addGroup(groupId, WRITE, false));
    assertEquals(Access.DENY, acl.canAccess(identity, WRITE));

    assertTrue(acl.remove(groupId, READ | WRITE));
    assertEquals(Access.UNKNOWN, acl.canAccess(identity, READ));
    assertEquals(Access.UNKNOWN, acl.evaluateAccess(identity, READ).getAccess());
  }

  @Test
  void identityDecisionTakesPrecedenceOverGroupDecision() {
    AccessControlList acl = new AccessControlList();
    UUID userId = UUID.randomUUID();
    UUID groupId = UUID.randomUUID();
    Group group = group(groupId, "operators");
    Identity identity = identity(userId, List.of(group));

    acl.addUser(userId, READ, false);
    acl.addGroup(groupId, READ, true);

    assertEquals(Access.DENY, acl.canAccess(identity, READ));
    assertEquals(userId, acl.evaluateAccess(identity, READ).getDecidingAuthId());
  }

  @Test
  void nullIdentityEvaluationIsUnknownAndCreateBuildsConfiguredAcl() {
    AccessControlList acl = new AccessControlList();
    AclAccessResult result = acl.evaluateAccess(null, READ);
    assertEquals(Access.UNKNOWN, result.getAccess());
    assertNull(result.getDecidingAuthId());

    UUID id = UUID.randomUUID();
    AccessControlList configured =
        acl.create(List.of(id + ":user:1:0"));
    assertNotNull(configured);
  }

  private static Identity identity(UUID id, List<Group> groups) {
    return new Identity(id, "alice", Map.of(), groups);
  }

  private static Group group(UUID id, String name) {
    return new Group(id, new GroupEntry(name, new TreeSet<>()));
  }
}
