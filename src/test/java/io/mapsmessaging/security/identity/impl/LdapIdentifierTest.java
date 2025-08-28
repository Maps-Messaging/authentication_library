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
import io.mapsmessaging.security.identity.impl.ldap.LdapAuth;
import io.mapsmessaging.security.identity.impl.ldap.LdapUser;
import io.mapsmessaging.security.jaas.PropertiesLoader;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.hashes.md5.Md5UnixPasswordHasher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import javax.naming.Context;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class LdapIdentifierTest {

  static Properties properties;

  @BeforeAll
  static void loadProperties() throws IOException {
    properties = PropertiesLoader.getProperties("ldap.properties");
  }

  @Test
  void simpleLoad() throws IOException, GeneralSecurityException {
    if (properties == null || properties.isEmpty()) {
      return;
    }
    Map<String, Object> map = new LinkedHashMap<>();
    map.put(Context.PROVIDER_URL, properties.getProperty("ldapUrl"));
    map.put(Context.SECURITY_PRINCIPAL, properties.getProperty("ldapUser"));
    map.put(Context.SECURITY_CREDENTIALS, properties.getProperty("ldapPassword"));

    map.put("passwordKeyName", "userpassword");

    map.put("searchBase", properties.getProperty("searchBase"));
    map.put("searchFilter", properties.getProperty("searchFilter"));

    map.put("groupSearchBase", properties.getProperty("groupSearchBase"));
    map.put("groupSearchFilter", properties.getProperty("groupSearchFilter"));

    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("ldap", map);
    Assertions.assertEquals(lookup.getClass(), LdapAuth.class);
    Assertions.assertEquals("ldap", lookup.getDomain());

    PasswordBuffer hash = lookup.getPasswordHash(properties.getProperty("username"));
    Assertions.assertNotNull(hash);
    Assertions.assertNotEquals(0, hash.getHash().length);
    String pwd = new String(hash.getHash());
    Assertions.assertEquals(properties.getProperty("hashedPassword"), pwd);
    PasswordHandler passwordHasher = PasswordHandlerFactory.getInstance().parse(hash.getHash());
    Assertions.assertEquals(Md5UnixPasswordHasher.class, passwordHasher.getClass());
    IdentityEntry identityEntry = lookup.findEntry(properties.getProperty("username"));
    Assertions.assertNotNull(identityEntry);
    Assertions.assertEquals(LdapUser.class, identityEntry.getClass());
    LdapUser ldapUser = (LdapUser) identityEntry;
    Map<String, String> attributes = new LinkedHashMap<>();
    ldapUser.setAttributeMap(attributes);
    Assertions.assertNotNull(attributes.get("homeDirectory"));
    Assertions.assertNotNull(ldapUser.getGroups());
    Assertions.assertEquals(4, ldapUser.getGroups().size());
    Assertions.assertEquals(ldapUser.getUsername(), properties.getProperty("username"));
    Assertions.assertNotNull(ldapUser.getDescription());
    Assertions.assertNotNull(ldapUser.getHomeDirectory());
    Assertions.assertNotNull(ldapUser.getSubject());
    Assertions.assertNotNull(ldapUser.getGroups());
    Assertions.assertFalse(ldapUser.getGroups().isEmpty());
    String groupName = ldapUser.getGroups().get(0).getName();
    Assertions.assertNotNull(lookup.findGroup(groupName).getName());
    Assertions.assertEquals(groupName, lookup.findGroup(groupName).getName());
    Assertions.assertNotNull(lookup.getEntries());
    Assertions.assertFalse(lookup.getEntries().isEmpty());
    Assertions.assertFalse(lookup.canManage());
    Assertions.assertNotNull(lookup.getGroups());
    Assertions.assertFalse(lookup.getGroups().isEmpty());
  }

  @Test
  void testInvalidConfig(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put(Context.SECURITY_PRINCIPAL, properties.getProperty("ldapUser"));
    map.put(Context.SECURITY_CREDENTIALS, properties.getProperty("ldapPassword"));

    map.put("passwordKeyName", "userpassword");

    map.put("searchBase", properties.getProperty("searchBase"));
    map.put("searchFilter", properties.getProperty("searchFilter"));

    map.put("groupSearchBase", properties.getProperty("groupSearchBase"));
    map.put("groupSearchFilter", properties.getProperty("groupSearchFilter"));

    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("ldap", map);
    Assertions.assertNull(lookup);
  }
}
