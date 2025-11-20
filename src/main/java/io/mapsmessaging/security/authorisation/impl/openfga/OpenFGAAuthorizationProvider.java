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
import dev.openfga.sdk.api.client.model.ClientCheckRequest;
import dev.openfga.sdk.api.client.model.ClientTupleKey;
import dev.openfga.sdk.api.client.model.ClientWriteRequest;
import dev.openfga.sdk.api.configuration.ClientCheckOptions;
import dev.openfga.sdk.api.configuration.ClientWriteOptions;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import lombok.Builder;
import lombok.NonNull;

public class OpenFGAAuthorizationProvider implements AuthorizationProvider {

  private final OpenFgaClient openFgaClient;
  private final String userType;
  private final String groupType;
  private final String tenantSeparator;
  private final String groupMemberRelation;
  private final String defaultAuthorizationModelId;

  @Builder
  public OpenFGAAuthorizationProvider(@NonNull OpenFgaClient openFgaClient,
                                      String defaultAuthorizationModelId,
                                      String userType,
                                      String groupType,
                                      String tenantSeparator,
                                      String groupMemberRelation
                                      ) {
    this.openFgaClient = openFgaClient;
    this.defaultAuthorizationModelId = defaultAuthorizationModelId;
    this.userType = userType != null ? userType : "user";
    this.groupType = groupType != null ? groupType : "group";
    this.tenantSeparator = tenantSeparator != null ? tenantSeparator : "/";
    this.groupMemberRelation = groupMemberRelation != null ? groupMemberRelation : "member";
  }

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
        .user("user:"+user)
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

  @Override
  public void grantAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource) {

    if (grantee == null || permission == null || protectedResource == null) {
      return;
    }
    ClientTupleKey tupleKey = new ClientTupleKey();

    if(grantee.type() == GranteeType.GROUP){
      tupleKey.user(toGranteeUser(grantee)+"#member");
    }
    else{
      tupleKey.user(toGranteeUser(grantee));
    }
    tupleKey.relation(permission.getName().toLowerCase());
    tupleKey._object(toObject(protectedResource));

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest()
        .writes(Collections.singletonList(tupleKey));

    ClientWriteOptions clientWriteOptions = new ClientWriteOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientWriteOptions.authorizationModelId(defaultAuthorizationModelId);
    }

    try {
      openFgaClient.write(clientWriteRequest, clientWriteOptions).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException executionException) {
      executionException.printStackTrace();
      // swallow or log via your logging framework
    } catch (FgaInvalidParameterException e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    }
  }

  @Override
  public void revokeAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {

    if (grantee == null || permission == null || protectedResource == null) {
      return;
    }
      ClientTupleKey tupleKey = new ClientTupleKey();
      if(grantee.type() == GranteeType.GROUP){
          tupleKey.user(toGranteeUser(grantee)+"#member");
      }
      else{
          tupleKey.user(toGranteeUser(grantee));
      }
      tupleKey.relation(permission.getName().toLowerCase());
      tupleKey._object(toObject(protectedResource));

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest()
        .deletes(Collections.singletonList(tupleKey));

    ClientWriteOptions clientWriteOptions = new ClientWriteOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientWriteOptions.authorizationModelId(defaultAuthorizationModelId);
    }

    try {
      openFgaClient.write(clientWriteRequest, clientWriteOptions).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      // swallow or log via your logging framework
    }
  }

  @Override
  public void deleteIdentity(Identity identity) {
    // Optional: clean up identity-related tuples if you want stricter hygiene.
  }

  @Override
  public void registerGroup(Group group) {
    // Typically nothing to do: group is just a type/id in OpenFGA.
  }

  @Override
  public void deleteGroup(Group group) {
    // Optional: clean up group-related tuples.
  }

  @Override
  public void addGroupMember(Group group, Identity identity) {

    if (group == null || identity == null) {
      return;
    }

    ClientTupleKey tupleKey = new ClientTupleKey()
        .user("user:"+identity.getId().toString())
        .relation(groupMemberRelation)
        ._object("group:"+group.getId().toString());

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest()
        .writes(Collections.singletonList(tupleKey));

    ClientWriteOptions clientWriteOptions = new ClientWriteOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientWriteOptions.authorizationModelId(defaultAuthorizationModelId);
    }

    try {
      openFgaClient.write(clientWriteRequest, clientWriteOptions).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      executionException.printStackTrace();
    }
  }

  @Override
  public void removeGroupMember(Group group, Identity identity) {

    if (group == null || identity == null) {
      return;
    }

    ClientTupleKey tupleKey = new ClientTupleKey()
        .user("user:"+identity.getId().toString())
        .relation(groupMemberRelation)
        ._object("group:"+group.getId().toString());

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest()
        .deletes(Collections.singletonList(tupleKey));

    ClientWriteOptions clientWriteOptions = new ClientWriteOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientWriteOptions.authorizationModelId(defaultAuthorizationModelId);
    }

    try {
      openFgaClient.write(clientWriteRequest, clientWriteOptions).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      // swallow or log
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
