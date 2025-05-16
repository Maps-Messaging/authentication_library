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

package io.mapsmessaging.security.identity.impl;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.apache.ApacheBasicAuth;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.hashes.md5.Md5PasswordHasher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ApacheIdentifierTest {

  @Test
  void simpleLoad() throws IOException, GeneralSecurityException {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/apache");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Apache-Basic-Auth", map);
    Assertions.assertEquals(lookup.getClass(), ApacheBasicAuth.class);
    Assertions.assertEquals("apache", lookup.getDomain());
    Assertions.assertEquals("Apache-Basic-Auth", lookup.getName());

    PasswordBuffer hash = lookup.getPasswordHash("test");
    Assertions.assertNotNull(hash);
    Assertions.assertNotEquals(0, hash.getHash().length);
    Assertions.assertNotNull(lookup.findGroup("user"));
    Assertions.assertNull(lookup.findGroup("user1"));

    Assertions.assertTrue(lookup.canManage());
    String pwd = new String(hash.getHash());
    Assertions.assertEquals("$apr1$9r.m87gj$5wXLLFhGKzknbwSLJj0HC1", pwd);
    PasswordHandler passwordHasher = PasswordHandlerFactory.getInstance().parse(hash.getHash());
    Assertions.assertEquals(Md5PasswordHasher.class, passwordHasher.getClass());
  }

  @Test
  void simpleEntryTest() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/apache");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Apache-Basic-Auth", map);
    IdentityEntry entry = lookup.findEntry("test");
    Assertions.assertNotNull(entry);
    Assertions.assertEquals("test:$apr1$9r.m87gj$5wXLLFhGKzknbwSLJj0HC1", entry.toString());
    Assertions.assertEquals(Md5PasswordHasher.class, entry.getPasswordHasher().getClass());
  }

  @Test
  void simpleGroupTest() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/apache");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Apache-Basic-Auth", map);
    IdentityEntry entry = lookup.findEntry("test");
    Assertions.assertNotNull(entry);
//    UserIdMap userIdMap = UserMapManagement.getGlobalInstance().get("apache:test");
//    Assertions.assertNotNull(userIdMap);
//    Assertions.assertEquals("test", userIdMap.getUsername());
    Assertions.assertTrue(entry.isInGroup("user"));
  }

  @Test
  void noUser() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/apache");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Apache-Basic-Auth", map);
    Assertions.assertEquals(lookup.getClass(), ApacheBasicAuth.class);
    Assertions.assertThrowsExactly(NoSuchUserFoundException.class, () -> lookup.getPasswordHash("noSuchUser"));
  }
}
