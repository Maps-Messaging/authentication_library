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

import com.github.javafaker.Faker;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.impl.apache.HtPasswdEntry;
import java.io.IOException;
import java.util.*;

public class AuthTestHelper {
  private static final Faker faker = new Faker();
  private static final Map<String, UUID> UUIDMap = new LinkedHashMap<>();

  public static Identity createIdentity(String username) {
    UUID uuid = UUIDMap.computeIfAbsent(username, k -> UUID.randomUUID());
    IdentityEntry identityEntry = new HtPasswdEntry(username, new char[0]);
    List<Group> groupList = new ArrayList<>();
    return new Identity(uuid, identityEntry, groupList);
  }

  public static List<String> generateGroupEntries(int numEntries, GroupMapManagement groupMapManagement) {
    List<String> aclEntries = new ArrayList<>();
    for (int i = 0; i < numEntries; i++) {
      String groupName = faker.space().nebula() + "-" + faker.space().galaxy();
      GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), groupName, "test");
      groupMapManagement.add(groupIdMap);
      String entry = groupIdMap.getAuthId() + " = Read|Write";
      aclEntries.add(entry);
    }
    return aclEntries;
  }

  public static Group createGroup(String groupName) {
    UUID uuid = UUIDMap.computeIfAbsent(groupName, k -> UUID.randomUUID());
    GroupEntry groupEntry = new GroupEntry(groupName, new HashSet<>());
    return new Group(uuid, groupEntry);
  }

  public static Identity createRandomIdenties(GroupMapManagement groupMapManagement) {
    Random random = new Random();
    String username = faker.name().firstName();
    String groupName = "group" + random.nextInt(100);
    return createIdentity(groupMapManagement,username,  groupName);
  }

  public static Identity createIdentity(GroupMapManagement groupMapManagement, String username, String groupName) {
    List<Group> groups = new ArrayList<>();
    if (groupMapManagement != null) {
      GroupIdMap groupIdMap = groupMapManagement.get("test:" + groupName);
      if (groupIdMap != null) {
        GroupEntry entry = new GroupEntry(groupIdMap.getGroupName(), new HashSet<>());

        Group group = new Group(groupIdMap.getAuthId(), entry);
        groups.add(group);
      }
    }
    IdentityEntry identityEntry = new HtPasswdEntry(username, new char[0]);
    return new Identity(UUID.randomUUID(), identityEntry, groups);
  }

  public static  AuthorizationProvider createOpenFgaAuthorizationProvider(ResourceTraversalFactory factory)throws Exception{
    Map<String, Object> config = new HashMap<>();
    Map<String, Object> authorisation = new HashMap<>();
    authorisation.put("enableCaching", false);
    authorisation.put("cachingTime", 10);
    config.put("authorisation", authorisation);
    Map<String, Object> openFgaMap = new HashMap<>();
    openFgaMap.put("uris", "http://10.140.62.152:8080");
    openFgaMap.put("storeId", "01KAF6PKR6YRJZ8RXXYXAJDX1E");
    openFgaMap.put("modelId", "01KB1X6KRRB2KRV1HK5K0WADTR");
    openFgaMap.put("connectionTimeout", 10);
    authorisation.put("openfga", openFgaMap);
    AuthorizationProvider provider = AuthorizationProviderFactory.getInstance().get("openFGA", config, TestPermissions.values(), factory);
    provider.reset();
    return provider;
  }


  public static  AuthorizationProvider createAclAuthorizationProvider(ResourceTraversalFactory factory) throws IOException {
    Map<String, Object> config = new HashMap<>();
    config.put("configDirectory", ".");
    Map<String, Object> certificateConfig = new HashMap<>();
    certificateConfig.put("type", "JKS");
    certificateConfig.put("path", "./authKeyStore.jks");
    certificateConfig.put("passphrase", "changeit");
    certificateConfig.put("alias", "default");
    certificateConfig.put("privateKey.name", "default");
    certificateConfig.put("privateKey.passphrase", "changeit");
    config.put("certificateStore", certificateConfig);


    AuthorizationProvider provider =  AuthorizationProviderFactory.getInstance().get("ACL", config, TestPermissions.values(), factory);
    provider.reset();
    return provider;
  }

  public static  AuthorizationProvider createCachingAuthorizationProvider(ResourceTraversalFactory factory) throws IOException {
    Map<String, Object> config = new HashMap<>();
    Map<String, Object> authorisation = new HashMap<>();
    config.put("cachingTime", 10);
    config.put("enableCaching", true);
    config.put("authorisation", authorisation);
    Map<String, Object> openFgaMap = new HashMap<>();
    openFgaMap.put("uris", "http://10.140.62.152:8080");
    openFgaMap.put("storeId", "01KAF6PKR6YRJZ8RXXYXAJDX1E");
    openFgaMap.put("modelId", "01KB1X6KRRB2KRV1HK5K0WADTR");
    openFgaMap.put("connectionTimeout", 10);
    authorisation.put("openfga", openFgaMap);

    AuthorizationProvider provider =  AuthorizationProviderFactory.getInstance().get("openFGA", config, TestPermissions.values(), factory);
    provider.reset();
    return provider;
  }

}
