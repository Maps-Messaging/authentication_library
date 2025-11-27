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
import dev.openfga.sdk.api.configuration.ClientBatchCheckOptions;
import dev.openfga.sdk.api.configuration.ClientConfiguration;
import dev.openfga.sdk.api.configuration.ClientReadOptions;
import dev.openfga.sdk.api.configuration.ClientWriteOptions;
import dev.openfga.sdk.api.model.TupleKey;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import dev.openfga.sdk.errors.FgaValidationError;
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

    String base = permission.getName().toLowerCase();      // e.g. "publish_server"
    String user = userType + ":" + identity.getId();       // e.g. "user:<uuid>"
    String object = toObject(protectedResource);           // "resource:tenant/ns/path"

    String denyRelation = "deny_" + base;
    String allowRelation = "allow_" + base;

    ClientBatchCheckItem denyRequest = new ClientBatchCheckItem()
        .user(user)
        .relation(denyRelation)
        ._object(object)
        .correlationId("deny");

    ClientBatchCheckItem allowRequest = new ClientBatchCheckItem()
        .user(user)
        .relation(allowRelation)
        ._object(object)
        .correlationId("allow");

    ClientBatchCheckRequest batchRequest = new ClientBatchCheckRequest()
        .checks(Arrays.asList(denyRequest, allowRequest));

    ClientBatchCheckOptions options = new ClientBatchCheckOptions();
    if (defaultAuthorizationModelId != null && !defaultAuthorizationModelId.isEmpty()) {
      options.authorizationModelId(defaultAuthorizationModelId);
    }

    boolean deny = false;
    boolean allow = false;

    try {
      requestCount.incrementAndGet();
      ClientBatchCheckResponse response = openFgaClient.batchCheck(batchRequest, options).get();
      for (ClientBatchCheckSingleResponse item : response.getResult()) {
        if ("deny".equals(item.getCorrelationId())) {
          deny = item.isAllowed();
        } else if ("allow".equals(item.getCorrelationId())) {
          allow =item.isAllowed();
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Access.DENY;
    } catch (ExecutionException | FgaInvalidParameterException e) {
      e.printStackTrace();
      return Access.DENY;
    } catch (FgaValidationError e) {
      e.printStackTrace();
      return Access.DENY;
    }

    if (deny) {
      return Access.DENY;
    }
    if (allow) {
      return Access.ALLOW;
    }
    return Access.UNKNOWN;
  }

  @Override
  public AccessDecision explainAccess(Identity identity,
                                      Permission permission,
                                      ProtectedResource protectedResource) {

    if (identity == null || permission == null || protectedResource == null) {
      return AccessDecision.builder()
          .identity(identity)
          .permission(permission)
          .protectedResource(protectedResource)
          .allowed(false)
          .decisionReason(DecisionReason.DEFAULT_DENY)
          .contributingGrants(List.of())
          .contributingGroups(List.of())
          .detailMessage("Missing identity, permission or resource")
          .build();
    }

    ResourceTraversal traversal = factory.create(protectedResource);

    while (traversal.hasMore()) {
      ProtectedResource currentResource = traversal.current();
      Access accessDecision = canAccessAtNode(identity, permission, currentResource);
      if (accessDecision == Access.UNKNOWN) {
        traversal.moveToParent();
        continue;
      }

      boolean allowed = (accessDecision == Access.ALLOW);

      // Find contributing grants at this node
      Collection<Grant> grantsAtResource = getGrantsForResource(currentResource);
      List<Grant> contributingGrants = new ArrayList<>();
      List<Group> contributingGroups = new ArrayList<>();

      boolean hasUserGrant = false;
      boolean hasGroupGrant = false;

      for (Grant grant : grantsAtResource) {
        if (!grant.getPermission().getName().equalsIgnoreCase(permission.getName())) {
          continue;
        }
        if (grant.isAllow() != allowed) {
          continue;
        }

        Grantee grantee = grant.getGrantee();
        if (grantee.type() == GranteeType.USER
            && grantee.id().equals(identity.getId())) {
          contributingGrants.add(grant);
          hasUserGrant = true;
        } else if (grantee.type() == GranteeType.GROUP) {
          Group group = findGroupById(identity, grantee.id());
          if (group != null) {
            contributingGrants.add(grant);
            contributingGroups.add(group);
            hasGroupGrant = true;
          }
        }
      }

      DecisionReason reason;
      boolean isExactResource =
          currentResource.getResourceType().equals(protectedResource.getResourceType())
              && currentResource.getResourceId().equals(protectedResource.getResourceId())
              && Objects.equals(currentResource.getTenant(), protectedResource.getTenant());

      if (allowed) {
        if (isExactResource) {
          if (hasUserGrant) {
            reason = DecisionReason.ALLOW_EXPLICIT_IDENTITY;
          } else if (hasGroupGrant) {
            reason = DecisionReason.ALLOW_EXPLICIT_GROUP;
          } else {
            reason = DecisionReason.ALLOW_EXPLICIT_IDENTITY;
          }
        } else {
          reason = DecisionReason.ALLOW_INHERITED_RESOURCE;
        }
      } else {
        if (isExactResource) {
          if (hasUserGrant) {
            reason = DecisionReason.DENY_EXPLICIT_IDENTITY;
          } else if (hasGroupGrant) {
            reason = DecisionReason.DENY_EXPLICIT_GROUP;
          } else {
            reason = DecisionReason.DENY_EXPLICIT_IDENTITY;
          }
        } else {
          reason = DecisionReason.DENY_INHERITED_RESOURCE;
        }
      }

      String detailMessage =
          "Decision=" + accessDecision
              + ", resource=" + toObject(currentResource)
              + ", requestedPermission=" + permission.getName().toLowerCase();

      return AccessDecision.builder()
          .identity(identity)
          .permission(permission)
          .protectedResource(protectedResource)
          .allowed(allowed)
          .decisionReason(reason)
          .contributingGrants(contributingGrants)
          .contributingGroups(contributingGroups)
          .detailMessage(detailMessage)
          .build();
    }

    // No node gave a definitive answer, default deny
    return AccessDecision.builder()
        .identity(identity)
        .permission(permission)
        .protectedResource(protectedResource)
        .allowed(false)
        .decisionReason(DecisionReason.DEFAULT_DENY)
        .contributingGrants(List.of())
        .contributingGroups(List.of())
        .detailMessage("No matching OpenFGA tuples, default deny")
        .build();
  }

  @Override
  public EffectiveAccess explainEffectiveAccess(Identity identity,
                                                ProtectedResource protectedResource) {

    Set<Permission> allowedPermissions = new HashSet<>();
    Set<Permission> deniedPermissions = new HashSet<>();
    Map<Permission, AccessDecision> decisionsByPermission = new HashMap<>();

    for (Permission perm : permissions.values()) {
      AccessDecision decision = explainAccess(identity, perm, protectedResource);
      decisionsByPermission.put(perm, decision);
      if (decision.isAllowed()) {
        allowedPermissions.add(perm);
      } else {
        deniedPermissions.add(perm);
      }
    }

    EffectiveAccess effectiveAccess = new EffectiveAccess();
    effectiveAccess.setIdentity(identity);
    effectiveAccess.setProtectedResource(protectedResource);
    effectiveAccess.setAllowedPermissions(allowedPermissions);
    effectiveAccess.setDeniedPermissions(deniedPermissions);
    effectiveAccess.setDecisionsByPermission(decisionsByPermission);

    return effectiveAccess;
  }

  private Group findGroupById(Identity identity, UUID groupId) {
    if (identity == null || identity.getGroupList() == null) {
      return null;
    }
    for (Group group : identity.getGroupList()) {
      if (groupId.equals(group.getId())) {
        return group;
      }
    }
    return null;
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
    String perm = "allow_"+permission.getName().toLowerCase();
    applyAccess(grantee, perm, protectedResource);
  }

  @Override
  public void denyAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource) {

    if (grantee == null || permission == null || protectedResource == null) {
      return;
    }
    String perm = "deny_"+permission.getName().toLowerCase();
    applyAccess(grantee, perm, protectedResource);
  }

  private void applyAccess(Grantee grantee,
                         String permission,
                         ProtectedResource protectedResource) {

    if (grantee == null || protectedResource == null) {
      return;
    }
    ClientTupleKey tupleKey = new ClientTupleKey();

    if (grantee.type() == GranteeType.GROUP) {
      tupleKey.user(toGranteeUser(grantee) + "#member");
    } else {
      tupleKey.user(toGranteeUser(grantee));
    }
    tupleKey.relation(permission);
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
    revoke(grantee, "allow_"+permission.getName().toLowerCase(), protectedResource);
    revoke(grantee, "deny"+permission.getName().toLowerCase(), protectedResource);
  }

  private void revoke(Grantee grantee, String perm,  ProtectedResource protectedResource) {
    ClientTupleKey tupleKey = new ClientTupleKey();
    if (grantee.type() == GranteeType.GROUP) {
      tupleKey.user(toGranteeUser(grantee) + "#member");
    } else {
      tupleKey.user(toGranteeUser(grantee));
    }
    tupleKey.relation(perm);
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
        String perm = key.getRelation();
        boolean allow = perm.startsWith("allow_");
        perm = perm.substring(perm.indexOf("_")+1);

        Permission permission = readHelper.toPermission(perm);
        if (permission == null) {
          continue;
        }

        ProtectedResource resource = readHelper.fromObject(key.getObject());
        if (resource == null) {
          continue;
        }

        result.add(new Grant(grantee, permission, resource, allow));
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
      executionException.printStackTrace();
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
