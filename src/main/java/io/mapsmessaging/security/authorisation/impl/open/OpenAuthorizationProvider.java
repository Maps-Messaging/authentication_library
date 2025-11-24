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

package io.mapsmessaging.security.authorisation.impl.open;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

public class OpenAuthorizationProvider implements AuthorizationProvider {

  public OpenAuthorizationProvider() {}

  @Override
  public String getName() {
    return "Open";
  }

  @Override
  public AuthorizationProvider create(ConfigurationProperties config, Permission[]  permissions){
    return this;
  }

  @Override
  public boolean canAccess(Identity identity, Permission permission, ProtectedResource protectedResource) {
    return true;
  }

  @Override
  public void grantAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) {
    //Nothing to do, this is open
  }

  @Override
  public void revokeAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) {
    //Nothing to do, this is open
  }

  @Override
  public void registerIdentity(UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void deleteIdentity(UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void registerGroup(UUID groupId) {
    //Nothing to do, this is open
  }

  @Override
  public void deleteGroup(UUID groupId) {
    //Nothing to do, this is open
  }

  @Override
  public void addGroupMember(UUID groupId, UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void removeGroupMember(UUID groupId, UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void registerResource(ProtectedResource protectedResource, ResourceCreationContext resourceCreationContext) {
    //Nothing to do, this is open
  }

  @Override
  public void deleteResource(ProtectedResource protectedResource) {
    //Nothing to do, this is open
  }

  @Override
  public Collection<Grant> getGrantsForIdentity(Identity identity) {
    return List.of();
  }

  @Override
  public Collection<Grant> getGrantsForGroup(Group group) {
    return List.of();
  }

  @Override
  public Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) {
    return List.of();
  }
}
