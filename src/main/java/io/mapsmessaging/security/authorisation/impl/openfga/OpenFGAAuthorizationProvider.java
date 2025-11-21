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

package io.mapsmessaging.security.authorisation.impl.openfga;

import dev.openfga.sdk.api.client.OpenFgaClient;
import dev.openfga.sdk.api.client.model.*;
import dev.openfga.sdk.api.configuration.ClientCheckOptions;
import dev.openfga.sdk.api.configuration.ClientReadOptions;
import dev.openfga.sdk.api.configuration.ClientWriteOptions;
import dev.openfga.sdk.api.model.TupleKey;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.AuthorizationProvider;
import io.mapsmessaging.security.authorisation.Grant;
import io.mapsmessaging.security.authorisation.Grantee;
import io.mapsmessaging.security.authorisation.GranteeType;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.ProtectedResource;
import io.mapsmessaging.security.authorisation.ResourceCreationContext;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

public class OpenFGAAuthorizationProvider implements AuthorizationProvider {

  private final OpenFgaClient openFgaClient;
  @Getter
  private final String userType;
  @Getter
  private final String groupType;
  @Getter
  private final String tenantSeparator;
  private final String groupMemberRelation;
  private final String defaultAuthorizationModelId;
  private final ReadHelper readHelper;
  @Getter
  private final Map<String, Permission> permissions;

  @Builder
  public OpenFGAAuthorizationProvider(@NonNull OpenFgaClient openFgaClient,
                                      String defaultAuthorizationModelId,
                                      Permission[] permission,
                                      String userType,
                                      String groupType,
                                      String tenantSeparator,
                                      String groupMemberRelation) {
    this.openFgaClient = openFgaClient;
    this.defaultAuthorizationModelId = defaultAuthorizationModelId;
    this.userType = userType != null ? userType : "user";
    this.groupType = groupType != null ? groupType : "group";
    this.tenantSeparator = tenantSeparator != null ? tenantSeparator : "/";
    this.groupMemberRelation = groupMemberRelation != null ? groupMemberRelation : "member";
    this.permissions = new ConcurrentHashMap<>();
    for (Permission permissionPrototype : permission) {
      permissions.put(permissionPrototype.getName().toLowerCase(),  permissionPrototype);
    }
    readHelper = new ReadHelper(this);
  }

  // =============================================================================================
  // Runtime check
  // =============================================================================================

  @Override
  public boolean canAccess(Identity identity,
                           Permission permission,
                           ProtectedResource protectedResource) {

    if (identity == null || permission == null || protectedResource == null) {
      return false;
    }

    String user = identity.getId().toString();
    String relation = permission.getName();
    String object = toObject(protectedResource);

    ClientCheckRequest clientCheckRequest = new ClientCheckRequest()
        .user(userType + ":" + user)
        .relation(relation)
        ._object(object);

    ClientCheckOptions clientCheckOptions = new ClientCheckOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientCheckOptions.authorizationModelId(defaultAuthorizationModelId);
    }

    try {
      CompletableFuture<dev.openfga.sdk.api.client.model.ClientCheckResponse> future =
          openFgaClient.check(clientCheckRequest, clientCheckOptions);
      dev.openfga.sdk.api.client.model.ClientCheckResponse response = future.get();
      return Boolean.TRUE.equals(response.getAllowed());
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
      return false;
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      return false;
    }
  }

  // =============================================================================================
  // Grants
  // =============================================================================================

  @Override
  public void grantAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource) {

    if (grantee == null || permission == null || protectedResource == null) {
      return;
    }
    ClientTupleKey tupleKey = new ClientTupleKey();

    if (grantee.type() == GranteeType.GROUP) {
      tupleKey.user(toGranteeUser(grantee) + "#member");
    } else {
      tupleKey.user(toGranteeUser(grantee));
    }
    tupleKey.relation(permission.getName().toLowerCase());
    tupleKey._object(toObject(protectedResource));

    ClientWriteRequest clientWriteRequest =
        new ClientWriteRequest().writes(Collections.singletonList(tupleKey));

    handleRequest(clientWriteRequest);
  }

  @Override
  public void revokeAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {

    if (grantee == null || permission == null || protectedResource == null) {
      return;
    }

    ClientTupleKey tupleKey = new ClientTupleKey();
    if (grantee.type() == GranteeType.GROUP) {
      tupleKey.user(toGranteeUser(grantee) + "#member");
    } else {
      tupleKey.user(toGranteeUser(grantee));
    }
    tupleKey.relation(permission.getName().toLowerCase());
    tupleKey._object(toObject(protectedResource));

    ClientWriteRequest clientWriteRequest =
        new ClientWriteRequest().deletes(Collections.singletonList(tupleKey));

    handleRequest(clientWriteRequest);
  }

  // =============================================================================================
  // Identity / group lifecycle
  // =============================================================================================

  @Override
  public void addGroupMember(UUID groupId, UUID identityId) {

    if (groupId == null || identityId == null) {
      return;
    }

    ClientTupleKey tupleKey = new ClientTupleKey()
        .user(toUser(identityId))
        .relation(groupMemberRelation)
        ._object(toGroupObject(groupId));

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest()
        .writes(Collections.singletonList(tupleKey));
    handleRequest(clientWriteRequest);
  }

  @Override
  public void removeGroupMember(UUID groupId, UUID identityId) {

    if (groupId == null || identityId == null) {
      return;
    }

    ClientTupleKey tupleKey = new ClientTupleKey()
        .user(toUser(identityId))
        .relation(groupMemberRelation)
        ._object(toGroupObject(groupId));

    ClientWriteRequest clientWriteRequest =
        new ClientWriteRequest().deletes(Collections.singletonList(tupleKey));
    handleRequest(clientWriteRequest);
  }

  // =============================================================================================
  // Resource lifecycle
  // =============================================================================================

  @Override
  public void registerResource(ProtectedResource protectedResource,
                               ResourceCreationContext resourceCreationContext) {

    if (protectedResource == null || resourceCreationContext == null) {
    }

   }

  @Override
  public void deleteResource(ProtectedResource protectedResource) {
    if (protectedResource == null) {
    }
  }

  // =============================================================================================
  // Grant introspection
  // =============================================================================================
  @Override
  public Collection<Grant> getGrantsForIdentity(Identity identity) {
    if (identity == null) {
      return Collections.emptyList();
    }

    ClientReadRequest request = new ClientReadRequest()
        .user(toUser(identity.getId()))
        ._object("resource:");

    return readGrants(request);
  }

  @Override
  public Collection<Grant> getGrantsForGroup(Group group) {
    if (group == null) {
      return Collections.emptyList();
    }

    // We stored group grants as "group:<id>#member"
    String user = groupType + ":" + group.getId() + "#" + groupMemberRelation;

    ClientReadRequest request = new ClientReadRequest()
        .user(user)
        ._object("resource:");

    return readGrants(request);
  }

  @Override
  public Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) {
    if (protectedResource == null) {
      return Collections.emptyList();
    }

    ClientReadRequest request = new ClientReadRequest()
        ._object(toObject(protectedResource));

    return readGrants(request);
  }


  public Collection<Grant> readGrants(ClientReadRequest request) {
    List<Grant> result = new ArrayList<>();
    String continuationToken = null;

    do {
      ClientReadOptions options = new ClientReadOptions();
      if (continuationToken != null && !continuationToken.isEmpty()) {
        options.continuationToken(continuationToken);
      }

      ClientReadResponse response;
      try {
        response = openFgaClient.read(request, options).get();
      } catch (InterruptedException interruptedException) {
        Thread.currentThread().interrupt();
        break;
      } catch (ExecutionException | FgaInvalidParameterException executionException) {
        executionException.printStackTrace();
        // TODO: log if you care
        break;
      }

      for (var tuple : response.getTuples()) {
        TupleKey key = tuple.getKey();
        Grantee grantee = readHelper.parseUserToGrantee(key.getUser());
        if (grantee == null) {
          continue;
        }

        Permission permission = readHelper.toPermission(key.getRelation());
        if (permission == null) {
          continue;
        }

        ProtectedResource resource = readHelper.fromObject(key.getObject());
        if (resource == null) {
          continue;
        }

        result.add(new Grant(grantee, permission, resource));
      }

      continuationToken = response.getContinuationToken();
    } while (continuationToken != null && !continuationToken.isEmpty());

    return result;
  }

  // =============================================================================================
  // Helpers
  // =============================================================================================

  private void handleRequest(ClientWriteRequest clientWriteRequest) {
    ClientWriteOptions clientWriteOptions = new ClientWriteOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientWriteOptions.authorizationModelId(defaultAuthorizationModelId);
    }
    try {
      openFgaClient.write(clientWriteRequest, clientWriteOptions).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      // ToDo: log this or surface upstream when you care
    }
  }

  private String toUser(UUID id) {
    return userType + ":" + id.toString();
  }

  private String toGroupObject(UUID id) {
    return groupType + ":" + id.toString();
  }

  private String toGranteeUser(Grantee grantee) {
    if (grantee.type() == GranteeType.USER) {
      return toUser(grantee.id());
    }
    return toGroupObject(grantee.id());
  }

  private String toObject(ProtectedResource protectedResource) {
    String resourceType = protectedResource.getResourceType();
    String resourceId = protectedResource.getResourceId();
    String tenant = protectedResource.getTenant();

    if (tenant != null && !tenant.isEmpty()) {
      return resourceType + ":" + tenant + tenantSeparator + resourceId;
    }
    return resourceType + ":" + resourceId;
  }
}
