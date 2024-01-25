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

package io.mapsmessaging.security.identity.impl;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.unix.UnixAuth;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.hashes.sha.UnixSha512PasswordHasher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class UnixIdentifierTest {

  @Test
  void simpleLoad() throws IOException, GeneralSecurityException {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/nix");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("unix", map);
    Assertions.assertNotNull(lookup.findGroup("admin.dojo"));
    Assertions.assertNull(lookup.findGroup("admin"));
    Assertions.assertEquals(lookup.getDomain(), "unix");
    Assertions.assertEquals(lookup.getClass(), UnixAuth.class);
    char[] hash = lookup.getPasswordHash("test");
    Assertions.assertNotNull(hash);
    Assertions.assertNotEquals(0, hash.length);
    String pwd = new String(hash);
    Assertions.assertEquals("$6$DVW4laGf$QwTuOOtd.1G3u2fs8d5/OtcQ73qTbwA.oAC1XWTmkkjrvDLEJ2WweTcBdxRkzfjQVfZCw3OVVBAMsIGMkH3On/", pwd);
    PasswordHandler passwordHasher = PasswordHandlerFactory.getInstance().parse(pwd);
    Assertions.assertEquals(UnixSha512PasswordHasher.class, passwordHasher.getClass());
  }

  @Test
  void simpleLoad2() throws IOException, GeneralSecurityException {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("passwd", "./src/test/resources/nix/passwd");
    map.put("passwordFile", "./src/test/resources/nix/shadow");
    map.put("groupFile", "./src/test/resources/nix/group");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("unix", map);
    Assertions.assertNotNull(lookup.findGroup("admin.dojo"));
    Assertions.assertNull(lookup.findGroup("admin"));
    Assertions.assertEquals(lookup.getDomain(), "unix");
    Assertions.assertEquals(lookup.getClass(), UnixAuth.class);
    char[] hash = lookup.getPasswordHash("test");
    Assertions.assertNotNull(hash);
    Assertions.assertNotEquals(0, hash.length);
    String pwd = new String(hash);
    Assertions.assertEquals("$6$DVW4laGf$QwTuOOtd.1G3u2fs8d5/OtcQ73qTbwA.oAC1XWTmkkjrvDLEJ2WweTcBdxRkzfjQVfZCw3OVVBAMsIGMkH3On/", pwd);
    PasswordHandler passwordHasher = PasswordHandlerFactory.getInstance().parse(pwd);
    Assertions.assertEquals(UnixSha512PasswordHasher.class, passwordHasher.getClass());
  }

  @Test
  void simpleEntryTest() {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/nix");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("unix", map);
    IdentityEntry entry = lookup.findEntry("test");
    Assertions.assertNotNull(entry);
    Assertions.assertEquals("test:$6$DVW4laGf$QwTuOOtd.1G3u2fs8d5/OtcQ73qTbwA.oAC1XWTmkkjrvDLEJ2WweTcBdxRkzfjQVfZCw3OVVBAMsIGMkH3On/", entry.toString());
    Assertions.assertEquals(UnixSha512PasswordHasher.class, entry.getPasswordHasher().getClass());
  }


  @Test
  void noUser() {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("configDirectory", "./src/test/resources/nix");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("unix", map);
    Assertions.assertEquals(lookup.getClass(), UnixAuth.class);
    Assertions.assertThrowsExactly(NoSuchUserFoundException.class, () -> lookup.getPasswordHash("noSuchUser"));
  }

}
