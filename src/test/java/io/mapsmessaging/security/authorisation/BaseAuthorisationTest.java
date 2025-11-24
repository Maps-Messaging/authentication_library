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

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.impl.apache.HtPasswdEntry;
import java.io.IOException;
import java.util.*;

public class BaseAuthorisationTest {
  private final Map<String, UUID> UUIDMap = new LinkedHashMap<>();

  protected Identity createIdentity(String username) {
    UUID uuid = UUIDMap.computeIfAbsent(username, k -> UUID.randomUUID());
    IdentityEntry identityEntry = new HtPasswdEntry(username, new char[0]);
    List<Group> groupList = new ArrayList<>();
    return new Identity(uuid, identityEntry, groupList);
  }

  protected Group createGroup(String groupName) {
    UUID uuid = UUIDMap.computeIfAbsent(groupName, k -> UUID.randomUUID());
    GroupEntry groupEntry = new GroupEntry(groupName, new HashSet<>());
    return new Group(uuid, groupEntry);
  }

  protected ProtectedResource createProtectedResource(String resourceName) {
    return new ProtectedResource("resource", resourceName, "");
  }

  protected Grantee createGranteeForIdentity(Identity identity) {
    return new Grantee(GranteeType.USER, identity.getId());
  }

  protected Grantee createGranteeForGroup(Group group) {
    return new Grantee(GranteeType.GROUP, group.getId());
  }


  protected AuthorizationProvider createOpenFgaAuthorizationProvider()throws Exception{
    Map<String, Object> config = new HashMap<>();
    Map<String, Object> authorisation = new HashMap<>();
    authorisation.put("enableCaching", false);
    authorisation.put("cachingTime", 10);
    config.put("authorisation", authorisation);
    Map<String, Object> openFgaMap = new HashMap<>();
    openFgaMap.put("uris", "http://10.140.62.152:8080");
    openFgaMap.put("storeId", "01KAF6PKR6YRJZ8RXXYXAJDX1E");
    openFgaMap.put("modelId", "01KAF6SSMG4T5WZY47FS12QZ0C");
    openFgaMap.put("connectionTimeout", 10);
    authorisation.put("openfga", openFgaMap);
    return AuthorizationProviderFactory.getInstance().get("openFGA", config, TestPermissions.values());
  }


  protected AuthorizationProvider createAclAuthorizationProvider() throws IOException {
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


    return AuthorizationProviderFactory.getInstance().get("ACL", config, TestPermissions.values());
  }

  protected AuthorizationProvider createCachingAuthorizationProvider() throws IOException {
    Map<String, Object> config = new HashMap<>();
    config.put("cachingTime", 10);
    config.put("enableCaching", true);
    Map<String, Object> certificateConfig = new HashMap<>();
    certificateConfig.put("type", "JKS");
    certificateConfig.put("path", "./authKeyStore.jks");
    certificateConfig.put("passphrase", "changeit");
    certificateConfig.put("alias", "default");
    certificateConfig.put("privateKey.name", "default");
    certificateConfig.put("privateKey.passphrase", "changeit");
    config.put("certificateStore", certificateConfig);


    return AuthorizationProviderFactory.getInstance().get("ACL", config, TestPermissions.values());
  }

}
