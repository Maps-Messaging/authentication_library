/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.access;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IdentityCoverageTest {

  @Test
  void identityRoundTripsAttributesAndGroups() throws Exception {
    UUID identityId = UUID.randomUUID();
    UUID groupId = UUID.randomUUID();

    DummyIdentityEntry entry = new DummyIdentityEntry("alice");
    Group group = new Group(
        groupId,
        new GroupEntry("operators", new TreeSet<>(List.of("alice"))));

    Identity original = new Identity(identityId, entry, List.of(group));
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    original.saveIdentity(output);

    Identity restored = new Identity(new ByteArrayInputStream(output.toByteArray()));

    assertEquals(identityId, restored.getId());
    assertEquals("alice", restored.getUsername());
    assertEquals("engineering", restored.getAttributes().get("department"));
    assertEquals(1, restored.getGroupList().size());
    assertEquals(groupId, restored.getGroupList().get(0).getId());
    assertEquals("operators", restored.getGroupList().get(0).getName());
  }

  @Test
  void identityRoundTripsEmptyCollections() throws Exception {
    UUID identityId = UUID.randomUUID();
    Identity original =
        new Identity(identityId, "nobody", new LinkedHashMap<>(), new ArrayList<>());
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    original.saveIdentity(output);

    Identity restored = new Identity(new ByteArrayInputStream(output.toByteArray()));

    assertEquals(identityId, restored.getId());
    assertEquals("nobody", restored.getUsername());
    assertTrue(restored.getAttributes().isEmpty());
    assertTrue(restored.getGroupList().isEmpty());
  }

  @Test
  void authContextNormalizesCommonAddressForms() {
    assertEquals("unknown", new AuthContext(null, "mqtt", "listener").ipAddress());
    assertEquals("unknown", new AuthContext("   ", "mqtt", "listener").ipAddress());
    assertEquals("127.0.0.1", new AuthContext("/127.0.0.1", "mqtt", "listener").ipAddress());
    assertEquals("192.0.2.10", new AuthContext("192.0.2.10:1883", "mqtt", "listener").ipAddress());
    assertEquals("::1", new AuthContext("[::1]:8883", "mqtt", "listener").ipAddress());
    assertEquals("2001:db8::1", new AuthContext("2001:db8::1", "mqtt", "listener").ipAddress());
  }

  private static final class DummyIdentityEntry extends IdentityEntry {

    private DummyIdentityEntry(String username) {
      this.username = username;
    }

    @Override
    public void setAttributeMap(Map<String, String> attributeMap) {
      attributeMap.put("username", username);
      attributeMap.put("department", "engineering");
    }
  }
}
