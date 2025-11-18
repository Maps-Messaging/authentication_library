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

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.authorisation.AuthorizationProvider;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.ProtectedResource;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.Subject;

public class AclAuthorizationProvider implements AuthorizationProvider {

  private final Map<ResourceKey, AccessControlList> accessControlListMap;
  private final AccessControlList accessControlListPrototype;
  private final List<String> configuration;

  public AclAuthorizationProvider(AccessControlList accessControlListPrototype,
                                  List<String> configuration) {
    this.accessControlListPrototype = accessControlListPrototype;
    this.configuration = configuration;
    this.accessControlListMap = new ConcurrentHashMap<>();
  }

  @Override
  public boolean canAccess(Subject subject,
                           Permission permission,
                           ProtectedResource protectedResource) {

    ResourceKey resourceKey = toResourceKey(protectedResource);
    AccessControlList accessControlList = accessControlListMap.get(resourceKey);

    if (accessControlList == null) {
      return false;
    }

    long requestedAccess = permission.getMask();
    return accessControlList.canAccess(subject, requestedAccess);
  }

  @Override
  public void grantAccess(Subject subject,
                          Permission permission,
                          ProtectedResource protectedResource) {

    AccessControlList accessControlList = getOrCreateAccessControlList(protectedResource);
    long requestedAccess = permission.getMask();
    UUID subjectId = SubjectHelper.getUniqueId(subject);
    accessControlList.add(subjectId, requestedAccess);
  }

  @Override
  public void revokeAccess(Subject subject,
                           Permission permission,
                           ProtectedResource protectedResource) {

    AccessControlList accessControlList = accessControlListMap.get(toResourceKey(protectedResource));
    if (accessControlList == null) {
      return;
    }

    long requestedAccess = permission.getMask();
    UUID subjectId = SubjectHelper.getUniqueId(subject);
    accessControlList.remove(subjectId, requestedAccess);
  }

  private AccessControlList getOrCreateAccessControlList(ProtectedResource protectedResource) {
    ResourceKey resourceKey = toResourceKey(protectedResource);
    return accessControlListMap.computeIfAbsent(
        resourceKey,
        key -> accessControlListPrototype.create(configuration)
    );
  }

  private ResourceKey toResourceKey(ProtectedResource protectedResource) {
    return new ResourceKey(
        protectedResource.getResourceType(),
        protectedResource.getResourceId(),
        protectedResource.getTenant()
    );
  }
}
