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

package io.mapsmessaging.security.authorisation.impl.acl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AclAuthorizationProvider implements AuthorizationProvider {

  private final Map<ResourceKey, AccessControlList> accessControlListMap;
  private final Map<Long, Permission> permissions;

  public AclAuthorizationProvider(Permission[] permission) {
    this.permissions = new  ConcurrentHashMap<>();
    this.accessControlListMap = new ConcurrentHashMap<>();
    for (Permission permissionPrototype : permission) {
      permissions.put(permissionPrototype.getMask(),  permissionPrototype);
    }
  }

  public String  getName() {
    return "ACL";
  }

  @Override
  public AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions) {
    return new AclAuthorizationProvider(permissions);
  }

  @Override
  public boolean canAccess(Identity identity,
                           Permission permission,
                           ProtectedResource protectedResource) {
    AccessControlList accessControlList = getOrCreateAccessControlList(protectedResource);
    long requestedAccess = permission.getMask();
    return accessControlList.canAccess(identity, requestedAccess);
  }

  @Override
  public void grantAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource){
    AccessControlList accessControlList = getOrCreateAccessControlList(protectedResource);
    long requestedAccess = permission.getMask();
    if (grantee.type() == GranteeType.USER) {
      accessControlList.addUser(grantee.id(), requestedAccess);
    }
    else{
      accessControlList.addGroup(grantee.id(), requestedAccess);
    }
    writeState();
  }


  @Override
  public void revokeAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {
    AccessControlList accessControlList = accessControlListMap.get(toResourceKey(protectedResource));
    if (accessControlList == null) {
      return;
    }

    long requestedAccess = permission.getMask();
    accessControlList.remove(grantee.id(), requestedAccess);
    writeState();
  }

  @Override
  public void registerIdentity(UUID identityId) {
    AuthorizationProvider.super.registerIdentity(identityId);
  }

  @Override
  public void deleteIdentity(UUID identityId) {
    for(AccessControlList accessControlList : accessControlListMap.values()) {
      accessControlList.remove(identityId, -1); // remove all
    }
    writeState();

  }

  @Override
  public void registerGroup(UUID groupId) {
    AuthorizationProvider.super.registerGroup(groupId);
  }

  @Override
  public void deleteGroup(UUID groupId) {
    for(AccessControlList accessControlList : accessControlListMap.values()) {
      accessControlList.remove(groupId, -1); // remove all
    }
    writeState();
  }

  @Override
  public void addGroupMember(UUID groupId, UUID identityId) {
    AuthorizationProvider.super.addGroupMember(groupId, identityId);
  }

  @Override
  public void removeGroupMember(UUID groupId, UUID identityId) {
    AuthorizationProvider.super.removeGroupMember(groupId, identityId);
  }

  @Override
  public void registerResource(ProtectedResource protectedResource, ResourceCreationContext resourceCreationContext) {
    AccessControlList accessControlList = getOrCreateAccessControlList(protectedResource);
    switch (resourceCreationContext.getInitialGrantPolicy()){
      case NONE:
      default:
        break;
      case OWNER_FULL:
        break;
      case OWNER_MANAGE:
        break;
      case INHERIT_FROM_PARENT:
        break;
    }
    writeState();

  }

  @Override
  public void deleteResource(ProtectedResource protectedResource) {
    accessControlListMap.remove(toResourceKey(protectedResource));
    writeState();

  }

  private AccessControlList getOrCreateAccessControlList(ProtectedResource protectedResource) {
    ResourceKey resourceKey = toResourceKey(protectedResource);
    return accessControlListMap.computeIfAbsent(
        resourceKey,
        key -> new AccessControlList()
    );
  }

  private ResourceKey toResourceKey(ProtectedResource protectedResource) {
    return new ResourceKey(
        protectedResource.getResourceType(),
        protectedResource.getResourceId(),
        protectedResource.getTenant()
    );
  }

  @Override
  public Collection<Grant> getGrantsForIdentity(Identity identity) {
    Collection<Grant>  collections = new ArrayList<>();
    Grantee grantee = Grantee.forIdentity(identity);
    for(Map.Entry<ResourceKey, AccessControlList> entry : accessControlListMap.entrySet()) {
      long accessMap = entry.getValue().getSubjectAccess(identity);
      processAccess(accessMap, entry.getKey(), grantee, collections);
    }
    return collections;
  }

  /**
   * List all grants where the given group is the grantee.
   */
  @Override
  public Collection<Grant> getGrantsForGroup(Group group) {
    Collection<Grant>  collections = new ArrayList<>();
    Grantee grantee = Grantee.forGroup(group);
    for(Map.Entry<ResourceKey, AccessControlList> entry : accessControlListMap.entrySet()) {
      long accessMap = entry.getValue().getGroupAccess(group);
      processAccess(accessMap, entry.getKey(), grantee, collections);
    }
    return collections;
  }

  @Override
  public Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) {
    Collection<Grant>  collections = new ArrayList<>();
    AccessControlList list = accessControlListMap.get(toResourceKey(protectedResource));
    if(list != null) {
      ResourceKey resourceKey = toResourceKey(protectedResource);
      for(AclEntry aclEntry:list.getAclEntries()){
        long accessMap = list.getRawAccess(aclEntry.getAuthId());
        Grantee grantee;
        if(aclEntry.isGroup()){
          grantee = new Grantee(GranteeType.GROUP, aclEntry.getAuthId());
        }
        else{
          grantee = new Grantee(GranteeType.USER, aclEntry.getAuthId());
        }
        processAccess(accessMap, resourceKey, grantee, collections);

      }
    }
    return collections;
  }

  private void processAccess(long accessMap, ResourceKey key, Grantee grantee, Collection<Grant> collections ){
    for(long x=0;x<64;x++){
      long mask = 1L<<x;
      if( (accessMap & mask) != 0){
        Permission p = permissions.get(mask);
        if(p != null){
          ProtectedResource protectedResource = new ProtectedResource(key.getType(), key.getName(), key.getTenant());
          Grant grant = new Grant(grantee, p, protectedResource);
          collections.add(grant);
        }
      }
    }
  }

  private void writeState(){
    Gson gson = new GsonBuilder()
        .disableHtmlEscaping()
        .setPrettyPrinting()
        .create();
    Map<String, AccessControlList> json = new LinkedHashMap<>();
    for (Map.Entry<ResourceKey, AccessControlList> entry : accessControlListMap.entrySet()) {
      json.put(entry.getKey().toString(), entry.getValue());
    }

    String out = gson.toJson(json);
  }

  private ResourceKey parse(String s) {
    if (s == null || s.isEmpty()) {
      throw new IllegalArgumentException("Cannot parse empty ResourceKey");
    }

    // Strip any leading/trailing wrappers just in case
    String trimmed = s.trim();

    // Expecting: type=resource, name=resource-1, tenant=
    String[] parts = trimmed.split(",");

    String type = null;
    String name = null;
    String tenant = "";

    for (String part : parts) {
      String p = part.trim();

      if (p.startsWith("type=")) {
        type = p.substring("type=".length());
      }
      else if (p.startsWith("name=")) {
        name = p.substring("name=".length());
      }
      else if (p.startsWith("tenant=")) {
        tenant = p.substring("tenant=".length());
      }
    }

    if (type == null || name == null) {
      throw new IllegalArgumentException("Invalid ResourceKey string: " + s);
    }

    return new ResourceKey(type, name, tenant);
  }
}
