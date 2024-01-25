/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.access;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.expiry.FixedExpiryPolicy;
import io.mapsmessaging.security.access.expiry.IdleAccessExpiryPolicy;
import io.mapsmessaging.security.access.expiry.NoExpiryPolicy;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AclEntryTest {

  @Test
  void testNoExpiryPolicy() {
    AclEntry entry = new AclEntry(UUID.randomUUID(), 0, new NoExpiryPolicy());
    assertFalse(entry.getExpiryPolicy().hasExpired(System.currentTimeMillis()));
  }

  @Test
  void testFixedExpiryPolicy() {
    long currentTime = System.currentTimeMillis();
    long expiryTime = currentTime + 1000; // expires in 1 second
    AclEntry entry = new AclEntry(UUID.randomUUID(), 0, new FixedExpiryPolicy(expiryTime));

    assertFalse(entry.getExpiryPolicy().hasExpired(currentTime));
    assertTrue(entry.getExpiryPolicy().hasExpired(expiryTime + 1));
  }

  @Test
  void testIdleAccessExpiryPolicy() {
    long idleTime = 1000; // 1 second idle time
    AclEntry entry = new AclEntry(UUID.randomUUID(), 0, new IdleAccessExpiryPolicy(idleTime));

    assertFalse(entry.getExpiryPolicy().hasExpired(System.currentTimeMillis()));
    assertTrue(entry.getExpiryPolicy().hasExpired(System.currentTimeMillis() + idleTime+1));
  }
}

