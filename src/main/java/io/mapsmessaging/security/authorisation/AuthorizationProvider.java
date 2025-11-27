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

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;

import java.io.IOException;
import java.util.UUID;

public interface AuthorizationProvider {

  String getName();

  AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions, ResourceTraversalFactory factory) throws IOException;

  void reset();

  // ==== Runtime check ====

  boolean canAccess(Identity identity,
                    Permission permission,
                    ProtectedResource protectedResource);


  // ==== Policy management (grants) ====

  /**
   * Grant access to a user or group (grantee) for a given permission on a resource.
   * Implementations decide how to persist/propagate this (ACL, OpenFGA, etc.).
   */
  default void grantAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {
    throw new UnsupportedOperationException("Grant not supported by this provider");
  }

  /**
   * Deny access to a user or group (grantee) for a given permission on a resource.
   * Implementations decide how to persist/propagate this (ACL, OpenFGA, etc.).
   */
  default void denyAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {
    throw new UnsupportedOperationException("Deny not supported by this provider");
  }

  /**
   * Revoke access from a user or group (grantee).
   */
  default void revokeAccess(Grantee grantee,
                            Permission permission,
                            ProtectedResource protectedResource) {
    throw new UnsupportedOperationException("Revoke not supported by this provider");
  }


  // ==== Identity / group lifecycle sync ====
  // Default no-ops so ACL-only providers don’t care; OpenFGA-backed ones override.

  /**
   * Called when a new identity is created in the authentication system.
   */
  default void registerIdentity(UUID identityId) {
    // default: no-op
  }

  /**
   * Called when an identity is deleted. Implementations should remove any
   * grants / tuples associated with this identity.
   */
  default void deleteIdentity(UUID identityId) {
    // default: no-op
  }

  /**
   * Called when a new group is created in the authentication system.
   */
  default void registerGroup(UUID groupId) {
    // default: no-op
  }

  /**
   * Called when a group is deleted. Implementations should remove any
   * grants / tuples associated with this group.
   */
  default void deleteGroup(UUID groupId) {
    // default: no-op
  }

  /**
   * Called when an identity is added to a group.
   */
  default void addGroupMember(UUID groupId, UUID identityId) {
    // default: no-op
  }

  /**
   * Called when an identity is removed from a group.
   */
  default void removeGroupMember(UUID groupId, UUID identityId) {
    // default: no-op
  }

  // ==== Resource lifecycle ====

  /**
   * Called when a new resource is created.
   * Implementations may install initial grants based on the creation context.
   */
  default void registerResource(ProtectedResource protectedResource,
                                ResourceCreationContext resourceCreationContext) {
    // default: no-op
  }

  /**
   * Called when a resource is deleted.
   * Implementations should remove any grants / tuples associated with this resource.
   */
  default void deleteResource(ProtectedResource protectedResource) {
    // default: no-op
  }

  default void startBatch(long timeout){
    // nothing to do, indicates, that a batch update is about to start
  }

  default void stopBatch(){
    // nothing to do, indicates a batch update has finished
  }

  // ==== Grant introspection ====

  /**
   * List all grants where the given identity is the grantee.
   */
  default java.util.Collection<Grant> getGrantsForIdentity(Identity identity) {
    throw new UnsupportedOperationException("Grant introspection not supported by this provider");
  }

  /**
   * List all grants where the given group is the grantee.
   */
  default java.util.Collection<Grant> getGrantsForGroup(Group group) {
    throw new UnsupportedOperationException("Grant introspection not supported by this provider");
  }

  /**
   * List all grants that apply to the given resource (any grantee).
   */
  default java.util.Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) {
    throw new UnsupportedOperationException("Grant introspection not supported by this provider");
  }


  default void grant(Identity identity, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forIdentity(identity);
    grantAccess(grantee, permission, resource);
  }

  default void grant(Group group, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forGroup(group);
    grantAccess(grantee, permission, resource);
  }

  default void revoke(Identity identity, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forIdentity(identity);
    revokeAccess(grantee, permission, resource);
  }

  default void revoke(Group group, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forGroup(group);
    revokeAccess(grantee, permission, resource);
  }

}
