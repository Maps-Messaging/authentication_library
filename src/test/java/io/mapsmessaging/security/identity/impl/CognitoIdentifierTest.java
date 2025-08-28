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

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.impl.cognito.CognitoAuth;
import io.mapsmessaging.security.jaas.PropertiesLoader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CognitoIdentifierTest {

  private static Properties properties;

  @BeforeAll
  static void loadProperties() throws IOException {
    properties = PropertiesLoader.getProperties("cognito.properties");
  }

  @Test
  void simpleLoad()  {
    Map<String, Object> map = new LinkedHashMap<>();
    for(Map.Entry<Object, Object> entry : properties.entrySet()){
      map.put(entry.getKey().toString(), entry.getValue());
    }
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Cognito", map);
    Assertions.assertEquals(lookup.getClass(), CognitoAuth.class);
    Assertions.assertTrue(lookup.canManage());
    Assertions.assertEquals("cognito", lookup.getDomain());
  }

  @Test
  void userAndGroupGetTests(){
    Map<String, Object> map = new LinkedHashMap<>();
    for(Map.Entry<Object, Object> entry : properties.entrySet()){
      map.put(entry.getKey().toString(), entry.getValue());
    }
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Cognito", map);
    Assertions.assertEquals(lookup.getClass(), CognitoAuth.class);
    List< IdentityEntry> entries = lookup.getEntries();
    Assertions.assertNotNull(entries);
    Assertions.assertFalse(entries.isEmpty());
    List<GroupEntry> groups = lookup.getGroups();
    Assertions.assertNotNull(groups);
    Assertions.assertFalse(groups.isEmpty());
  }

  @Test
  void userCreateAndDeleteTests() throws IOException, GeneralSecurityException {
    Map<String, Object> map = new LinkedHashMap<>();
    for(Map.Entry<Object, Object> entry : properties.entrySet()){
      map.put(entry.getKey().toString(), entry.getValue());
    }
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Cognito", map);
    Assertions.assertEquals(lookup.getClass(), CognitoAuth.class);
    IdentityEntry identityEntry = lookup.getEntries().stream().filter(user -> user.getUsername().equals("testUser")).findFirst().orElse(null);
    if(identityEntry != null){
      lookup.deleteUser("testUser");
    }
    lookup.createUser("testUser", "dummy password".toCharArray(), null);

    Assertions.assertArrayEquals(new char[0], lookup.getPasswordHash("testUser").getHash() );
    identityEntry = lookup.findEntry("testUser");
    Assertions.assertArrayEquals(new char[0], identityEntry.getPassword().getHash() );
    Assertions.assertNotNull(identityEntry);
    Assertions.assertEquals("testUser", identityEntry.getUsername());
    Assertions.assertTrue(lookup.deleteUser(identityEntry.getUsername()));
    identityEntry = lookup.getEntries().stream().filter(user -> user.getUsername().equals("testUser")).findFirst().orElse(null);
    Assertions.assertNull(identityEntry);
  }


  @Test
  void groupCreateAndDeleteTests() throws IOException, GeneralSecurityException {
    Map<String, Object> map = new LinkedHashMap<>();
    for(Map.Entry<Object, Object> entry : properties.entrySet()){
      map.put(entry.getKey().toString(), entry.getValue());
    }
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("Cognito", map);
    Assertions.assertEquals(lookup.getClass(), CognitoAuth.class);
    GroupEntry groupEntry = lookup.getGroups().stream().filter(group -> group.getName().equals("testGroup")).findFirst().orElse(null);
    if(groupEntry != null){
      lookup.deleteGroup("testGroup");
    }
    lookup.createGroup("testGroup");
    groupEntry = lookup.findGroup("testGroup");
    Assertions.assertNotNull(groupEntry);
    Assertions.assertEquals("testGroup", groupEntry.getName());
    Assertions.assertTrue(lookup.deleteGroup(groupEntry.getName()));
    groupEntry = lookup.getGroups().stream().filter(group -> group.getName().equals("testGroup")).findFirst().orElse(null);
    Assertions.assertNull(groupEntry);
  }


}
