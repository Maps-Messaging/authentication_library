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
import dev.openfga.sdk.api.configuration.ClientConfiguration;
import dev.openfga.sdk.api.configuration.ClientReadOptions;
import dev.openfga.sdk.api.configuration.ClientWriteOptions;
import dev.openfga.sdk.api.model.TupleKey;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;
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
  private final ResourceTraversalFactory factory;
  private final TuplePresenceCache tuplePresenceCache;
  @Getter
  private final Map<String, Permission> permissions;
  private final AtomicLong requestCount;

  @Builder
  public OpenFGAAuthorizationProvider(@NonNull OpenFgaClient openFgaClient,
                                      String defaultAuthorizationModelId,
                                      Permission[] permission,
                                      ResourceTraversalFactory factory,
                                      String userType,
                                      String groupType,
                                      String tenantSeparator,
                                      String groupMemberRelation) {
    this.openFgaClient = openFgaClient;
    this.factory = factory;
    this.defaultAuthorizationModelId = defaultAuthorizationModelId;
    this.requestCount = new AtomicLong(0);
    this.userType = userType != null ? userType : "user";
    this.groupType = groupType != null ? groupType : "group";
    this.tenantSeparator = tenantSeparator != null ? tenantSeparator : "/";
    this.groupMemberRelation = groupMemberRelation != null ? groupMemberRelation : "member";
    this.permissions = new ConcurrentHashMap<>();
    this.tuplePresenceCache = new TuplePresenceCache(openFgaClient, userType, groupType,groupMemberRelation, 10_000);
    for (Permission permissionPrototype : permission) {
      permissions.put(permissionPrototype.getName().toLowerCase(),  permissionPrototype);
    }
    readHelper = new ReadHelper(this);
  }

  public OpenFGAAuthorizationProvider(){
    this.openFgaClient = null;
    this.defaultAuthorizationModelId = null;
    this.factory = null;
    this.userType = null;
    this.groupType = null;
    this.tenantSeparator = null;
    this.groupMemberRelation = null;
    this.tuplePresenceCache = null;
    this.permissions = new ConcurrentHashMap<>();
    this.readHelper = new ReadHelper(this);
    this.requestCount = new AtomicLong(0);
  }

  @Override
  public   AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions, ResourceTraversalFactory factory)throws IOException{
    ConfigurationProperties authorisation = (ConfigurationProperties) config.get("authorisation");

    ConfigurationProperties fgaProperties = (ConfigurationProperties) authorisation.get("openfga");
    String uris = fgaProperties.getProperty("uris");
    String storeId = fgaProperties.getProperty("storeId");
    String modelId = fgaProperties.getProperty("modelId");
    String uType = fgaProperties.getProperty("userType");
    String gType = fgaProperties.getProperty("groupType");
    String tSeparator = fgaProperties.getProperty("tenantSeparator");
    String gMemberRelation = fgaProperties.getProperty("groupMemberRelation");
    long connectionTimeout = fgaProperties.getLongProperty("connectionTimeout", 10);

    ClientConfiguration clientConfiguration = new ClientConfiguration();
    clientConfiguration.apiUrl(uris);
    clientConfiguration.storeId(storeId);
    clientConfiguration.connectTimeout(Duration.ofSeconds(connectionTimeout));
    try {
      OpenFgaClient client = new OpenFgaClient(clientConfiguration);
      return new OpenFGAAuthorizationProvider(client, modelId, permissions, factory, uType, gType, tSeparator, gMemberRelation);
    }
    catch (FgaInvalidParameterException e) {
      throw new IOException(e);
    }
  }

  public long getRequestCount() {
    return requestCount.get();
  }
  // =============================================================================================
  // Runtime check
  // =============================================================================================

  @Override
  public String getName() {
    return "OpenFGA";
  }

  @Override
  public void reset() {
    if (openFgaClient == null) {
      return;
    }

    ClientReadRequest readAll = new ClientReadRequest();
    String continuationToken = null;

    do {
      ClientReadOptions readOptions = new ClientReadOptions();
      if (continuationToken != null && !continuationToken.isEmpty()) {
        readOptions.continuationToken(continuationToken);
      }
      ClientReadResponse response  = handleReadRequest(readAll, readOptions);
      if(response == null){
        break;
      }
      List<ClientTupleKeyWithoutCondition> deletes =
          response.getTuples().stream()
              .map(
                  tuple -> {
                    TupleKey key = tuple.getKey();
                    ClientTupleKeyWithoutCondition del = new ClientTupleKeyWithoutCondition();
                    del.user(key.getUser());
                    del.relation(key.getRelation());
                    del._object(key.getObject());
                    return del;
                  })
              .toList();

      if (!deletes.isEmpty()) {
        ClientWriteRequest writeRequest = ClientWriteRequest.ofDeletes(deletes);
        handleRequest(writeRequest);
      }
      continuationToken = response.getContinuationToken();
    } while (!continuationToken.isEmpty());
  }

  @Override
  public boolean canAccess(Identity identity,
                           Permission permission,
                           ProtectedResource protectedResource) {
    if (identity == null || permission == null || protectedResource == null) {
      return false;
    }

    ResourceTraversal resourceTraversal = factory.create(protectedResource);
    while (resourceTraversal.hasMore()) {
      ProtectedResource currentResource = resourceTraversal.current();
      Access accessDecision = canAccessAtNode(identity, permission, currentResource);
      switch (accessDecision) {
        case ALLOW -> {
          return  true;
        }
        case DENY -> {
          return false;
        }
        default -> {
          // nothing to do
        }
      }
      resourceTraversal.moveToParent();
    }
    return false; // default deny
  }

  private Access canAccessAtNode(Identity identity,
                                 Permission permission,
                                 ProtectedResource protectedResource) {

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

    boolean allowed;
    try {
      requestCount.incrementAndGet();
      ClientCheckResponse response = openFgaClient.check(clientCheckRequest, clientCheckOptions).get();
      allowed = Boolean.TRUE.equals(response.getAllowed());
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
      return Access.DENY;
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      executionException.printStackTrace();
      return Access.DENY;
    }

    if (allowed) {
      return Access.ALLOW;
    }

    // not allowed: check if this node is authoritative for this identity
    boolean hasLocalAcl = tuplePresenceCache.hasAnyTuplesForIdentityOnObject(identity, object);

    if (hasLocalAcl) {
      return Access.DENY;
    }

    return Access.UNKNOWN;
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

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest().writes(Collections.singletonList(tupleKey));
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

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest().deletes(Collections.singletonList(tupleKey));

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

    ClientWriteRequest clientWriteRequest = new ClientWriteRequest().deletes(Collections.singletonList(tupleKey));
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

      requestCount.incrementAndGet();
      ClientReadResponse response = handleReadRequest(request, options);
      if(response == null) {
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

  private ClientReadResponse handleReadRequest(ClientReadRequest clientReadRequest,  ClientReadOptions options) {
    try {
      requestCount.incrementAndGet();
      return openFgaClient.read(clientReadRequest, options).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException | FgaInvalidParameterException executionException) {
      // ToDo: log this or surface upstream when you care
    }
    return null;
  }


  private void handleRequest(ClientWriteRequest clientWriteRequest) {
    ClientWriteOptions clientWriteOptions = new ClientWriteOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      clientWriteOptions.authorizationModelId(defaultAuthorizationModelId);
    }
    try {
      requestCount.incrementAndGet();
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
