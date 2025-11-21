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

import io.mapsmessaging.security.authorisation.impl.acl.AclEntry;
import io.mapsmessaging.security.authorisation.impl.acl.expiry.AccessEntryExpiryPolicy;
import io.mapsmessaging.security.authorisation.impl.acl.expiry.FixedExpiryPolicy;
import io.mapsmessaging.security.authorisation.impl.acl.expiry.IdleAccessExpiryPolicy;
import io.mapsmessaging.security.authorisation.impl.acl.expiry.NoExpiryPolicy;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AclEntryTest {

  @Test
  void testNoExpiryPolicy() {
    AclEntry entry = new AclEntry(UUID.randomUUID(), 0, false,  new NoExpiryPolicy());
    assertFalse(entry.getExpiryPolicy().hasExpired(System.currentTimeMillis()));
  }

  @Test
  void testFixedExpiryPolicy() {
    long currentTime = System.currentTimeMillis();
    long expiryTime = currentTime + 1000; // expires in 1 second
    AclEntry entry = new AclEntry(UUID.randomUUID(), 0, false, new FixedExpiryPolicy(expiryTime));

    assertFalse(entry.getExpiryPolicy().hasExpired(currentTime));
    assertTrue(entry.getExpiryPolicy().hasExpired(expiryTime + 1));
  }

  @Test
  void testIdleAccessExpiryPolicy() {
    long idleTime = 1000; // 1 second idle time
    AclEntry entry = new AclEntry(UUID.randomUUID(), 0, false, new IdleAccessExpiryPolicy(idleTime));

    assertFalse(entry.getExpiryPolicy().hasExpired(System.currentTimeMillis()));
    assertTrue(entry.getExpiryPolicy().hasExpired(System.currentTimeMillis() + idleTime+1));
  }


  @Test
  void testAllArgsConstructor() {
    UUID authId = UUID.randomUUID();
    long permissions = 12345L;
    AccessEntryExpiryPolicy expiryPolicy = new NoExpiryPolicy(); // Replace with actual policy implementation

    AclEntry entry = new AclEntry(authId, permissions,false, expiryPolicy);

    assertEquals(authId, entry.getAuthId(), "Auth ID should match the one set in constructor");
    assertEquals(permissions, entry.getPermissions(), "Permissions should match the ones set in constructor");
    assertSame(expiryPolicy, entry.getExpiryPolicy(), "Expiry policy should match the one set in constructor");
  }

  @Test
  void testConstructorWithDefaultExpiryPolicy() {
    UUID authId = UUID.randomUUID();
    long permissions = 12345L;

    AclEntry entry = new AclEntry(authId, false, permissions);

    assertEquals(authId, entry.getAuthId(), "Auth ID should match the one set in constructor");
    assertEquals(permissions, entry.getPermissions(), "Permissions should match the ones set in constructor");
    assertInstanceOf(NoExpiryPolicy.class, entry.getExpiryPolicy(), "Default expiry policy should be NoExpiryPolicy");
  }

  @Test
  void testMatchesMethod() {
    UUID authId = UUID.randomUUID();
    AclEntry entry = new AclEntry(authId, false, 12345L);

    assertTrue(entry.matches(authId), "Matches should return true for the same authId");
    assertFalse(entry.matches(UUID.randomUUID()), "Matches should return false for a different authId");
  }
}

