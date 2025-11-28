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

import static io.mapsmessaging.security.certificates.CertificateUtils.generateSelfSignedCertificateSecret;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.CertificateManagerFactory;
import io.mapsmessaging.security.certificates.CertificateWithPrivateKey;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.Data;
import lombok.Value;

public class AclAuthorizationProvider implements AuthorizationProvider {
  private static final String ACL_SECRET_KEY_ALIAS = "acl.state.key";

  private final Map<ResourceKey, AccessControlList> accessControlListMap;
  private final Map<Long, Permission> permissions;
  private final AclSaveState saveState;
  private final AtomicBoolean batchStarted;
  private final ResourceTraversalFactory factory;

  public AclAuthorizationProvider() {
    accessControlListMap = null;
    permissions = null;
    factory = null;
    saveState = null;
    batchStarted = new AtomicBoolean(false);
  }

  public AclAuthorizationProvider(String config, Permission[] permission, AclSaveState saveState, ResourceTraversalFactory factory) {
    this.permissions = new  ConcurrentHashMap<>();
    this.factory = factory;
    this.accessControlListMap = new ConcurrentHashMap<>();
    for (Permission permissionPrototype : permission) {
      permissions.put(permissionPrototype.getMask(),  permissionPrototype);
    }
    this.saveState = saveState;
    batchStarted = new AtomicBoolean(false);
    readState(config);
  }

  @Override
  public String  getName() {
    return "ACL";
  }

  @Override
  public void reset(){
    accessControlListMap.clear();
    writeState();
  }

  @Override
  public AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions,  ResourceTraversalFactory factory) throws IOException {
    try {
      ConfigurationProperties certificateConfig = (ConfigurationProperties)config.get("certificateStore");
      CertificateManager certificateManager = CertificateManagerFactory.getInstance().getManager(certificateConfig);
      String keyPassword = certificateConfig.getProperty("passphrase");
      SecretKey secretKey = loadOrCreateAclKey(certificateManager, keyPassword.toCharArray());
      String filePath = config.getProperty("configDirectory", ".");
      if(!filePath.endsWith("/")) {
        filePath = filePath + "/";
      }
      filePath = filePath + ".acl_enc.dat";
      AclLoadState aclLoadState = new AclLoadState(filePath, secretKey);
      AclSaveState aclSaveState = new AclSaveState(filePath, secretKey);

      String aclLoad = aclLoadState.loadState();
      return new AclAuthorizationProvider(aclLoad, permissions, aclSaveState, factory);
    } catch (IOException|GeneralSecurityException e) {
      // ToDo:: Log This as fatal!
      throw new IOException(e);
    }
  }

  @Override
  public void startBatch(long timeout){
    batchStarted.set(true);
  }

  @Override
  public void stopBatch(){
    batchStarted.set(false);
    writeState();
  }

  public boolean hasAllAccess(AuthRequest[] requests){
    for(AuthRequest requestPrototype : requests){
      if(!canAccess(requestPrototype.getIdentity(), requestPrototype.getPermission(),requestPrototype.getProtectedResource())){
        return false;
      }
    }
    return true;
  }

  public boolean hasOneAccess(AuthRequest[] requests){
    for(AuthRequest requestPrototype : requests){
      if(canAccess(requestPrototype.getIdentity(), requestPrototype.getPermission(),requestPrototype.getProtectedResource())){
        return true;
      }
    }
    return false;
  }

  @Override
  public boolean canAccess(Identity identity,
                           Permission permission,
                           ProtectedResource protectedResource) {
    ResourceTraversal traversal = factory.create(protectedResource);
    long requestedAccess = permission.getMask();
    while (traversal.hasMore()) {
      ProtectedResource current = traversal.current();
      AccessControlList accessControlList = findAccessControlList(current);
      if (accessControlList != null) {
        Access decision = accessControlList.canAccess(identity, requestedAccess);
        if (decision == Access.DENY) {
          return false;
        }
        if (decision == Access.ALLOW) {
          return true;
        }
      }
      traversal.moveToParent();
    }
    return false; // default deny
  }

  public AccessDecision explainAccess(Identity identity,
                                      Permission permission,
                                      ProtectedResource protectedResource) {
    ResourceTraversal traversal = factory.create(protectedResource);
    long requestedAccess = permission.getMask();
    ProtectedResource currentResource;
    while (traversal.hasMore()) {
      currentResource = traversal.current();
      AccessControlList accessControlList = findAccessControlList(currentResource);
      if (accessControlList != null) {
        AclAccessResult result = accessControlList.evaluateAccess(identity, requestedAccess);
        Access access = result.getAccess();
        if (access != Access.UNKNOWN) {
          boolean allowed = (access == Access.ALLOW);

          DecisionReason reason;
          if (allowed) {
            if (currentResource.equals(protectedResource)) {
              reason = result.isGroupDecision()
                  ? DecisionReason.ALLOW_EXPLICIT_GROUP
                  : DecisionReason.ALLOW_EXPLICIT_IDENTITY;
            } else {
              reason = DecisionReason.ALLOW_INHERITED_RESOURCE;
            }
          } else {
            if (currentResource.equals(protectedResource)) {
              reason = result.isGroupDecision()
                  ? DecisionReason.DENY_EXPLICIT_GROUP
                  : DecisionReason.DENY_EXPLICIT_IDENTITY;
            } else {
              reason = DecisionReason.DENY_INHERITED_RESOURCE;
            }
          }

          List<Grant> contributingGrants = List.of();
          List<Group> contributingGroups = List.of();

          AclEntry aclEntry = result.getAclEntry();
          UUID decidingId = result.getDecidingAuthId();

          if (aclEntry != null && decidingId != null) {
            boolean grantAllow = (aclEntry.getAllow() & requestedAccess) != 0L;
            Grantee grantee = aclEntry.isGroup()
                ? new Grantee(GranteeType.GROUP, decidingId)
                : new Grantee(GranteeType.USER, decidingId);

            ProtectedResource decisionResource =
                new ProtectedResource(
                    currentResource.getResourceType(),
                    currentResource.getResourceId(),
                    currentResource.getTenant());

            Grant grant = new Grant(grantee, permission, decisionResource, grantAllow);
            contributingGrants = List.of(grant);

            if (result.isGroupDecision()) {
              Group group = findGroupById(identity, decidingId);
              if (group != null) {
                contributingGroups = List.of(group);
              }
            }
          }

          String detailMessage = "Decision=" + access
              + ", resource=" + currentResource
              + ", requestedPermission=" + permission.getName();

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
      }
      traversal.moveToParent();
    }

    // No ACL matched, default deny
    return AccessDecision.builder()
        .identity(identity)
        .permission(permission)
        .protectedResource(protectedResource)
        .allowed(false)
        .decisionReason(DecisionReason.DEFAULT_DENY)
        .contributingGrants(List.of())
        .contributingGroups(List.of())
        .detailMessage("No ACL entry matched, default deny")
        .build();
  }

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


  @Override
  public void grantAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource){
    AccessControlList accessControlList = getOrCreateAccessControlList(protectedResource);
    long requestedAccess = permission.getMask();
    if (grantee.type() == GranteeType.USER) {
      accessControlList.addUser(grantee.id(), requestedAccess, true);
    }
    else{
      accessControlList.addGroup(grantee.id(), requestedAccess, true);
    }
    writeState();
  }


  public void denyAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource) {
    AccessControlList accessControlList = getOrCreateAccessControlList(protectedResource);
    long requestedAccess = permission.getMask();
    if (grantee.type() == GranteeType.USER) {
      accessControlList.addUser(grantee.id(), requestedAccess, false);
    }
    else{
      accessControlList.addGroup(grantee.id(), requestedAccess, false);
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
    writeState();
  }

  @Override
  public void deleteResource(ProtectedResource protectedResource) {
    accessControlListMap.remove(toResourceKey(protectedResource));
    writeState();

  }

  private AccessControlList findAccessControlList(ProtectedResource protectedResource) {
    ResourceKey resourceKey = toResourceKey(protectedResource);
    return accessControlListMap.get(resourceKey);
  }

  private AccessControlList getOrCreateAccessControlList(ProtectedResource protectedResource) {
    ResourceKey resourceKey = toResourceKey(protectedResource);
    return accessControlListMap.computeIfAbsent(resourceKey, key -> new AccessControlList());
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
      processAccess(accessMap, entry.getKey(), grantee, collections, true);
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
      processAccess(accessMap, entry.getKey(), grantee, collections, true);
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
        processAccess(accessMap, resourceKey, grantee, collections, true);

      }
    }
    return collections;
  }

  private void processAccess(long accessMap, ResourceKey key, Grantee grantee, Collection<Grant> collections, boolean allow ){
    for(long x=0;x<64;x++){
      long mask = 1L<<x;
      if( (accessMap & mask) != 0){
        Permission p = permissions.get(mask);
        if(p != null){
          ProtectedResource protectedResource = new ProtectedResource(key.getType(), key.getName(), key.getTenant());
          Grant grant = new Grant(grantee, p, protectedResource, allow);
          collections.add(grant);
        }
      }
    }
  }

  private void writeState() {
    if(batchStarted.get()) return; // in middle of batch
    Gson gson = new GsonBuilder()
        .disableHtmlEscaping()
        .setPrettyPrinting()
        .create();

    AuthorizationState authorizationState = new AuthorizationState();
    authorizationState.setVersion(1);

    List<AuthorizationStateEntry> entries = new ArrayList<>();
    for (Map.Entry<ResourceKey, AccessControlList> entry : accessControlListMap.entrySet()) {
      AuthorizationStateEntry stateEntry = new AuthorizationStateEntry(entry.getKey(), entry.getValue());
      entries.add(stateEntry);
    }
    authorizationState.setEntries(entries);
    String data = gson.toJson(authorizationState);
    try {
      saveState.saveState(data);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void readState(String state) {
    if (state == null || state.isEmpty()) {
      return;
    }

    Gson gson = new GsonBuilder()
        .disableHtmlEscaping()
        .setPrettyPrinting()
        .create();

    AuthorizationState authorizationState;
    try {
      authorizationState = gson.fromJson(state, AuthorizationState.class);
      if (authorizationState == null) {
        return;
      }
    } catch (JsonSyntaxException e) {
      // ToDo: Log a FATAL ERROR!!!!!
      return;
    }

    // Optional: check version here if you ever change the format
    // int version = authorizationState.getVersion();

    List<AuthorizationStateEntry> entries = authorizationState.getEntries();
    if (entries == null) {
      return;
    }

    for (AuthorizationStateEntry entry : entries) {
      ResourceKey resourceKey = entry.getKey();
      AccessControlList accessControlList = entry.getAcl();
      if (resourceKey != null && accessControlList != null) {
        accessControlListMap.put(resourceKey, accessControlList);
      }
    }
  }

  @Data
  private static class AuthorizationState {
    private int version;
    private List<AuthorizationStateEntry> entries;
  }

  @Value
  private static class AuthorizationStateEntry {
    ResourceKey key;
    AccessControlList acl;
  }

  private SecretKey loadOrCreateAclKey(
      CertificateManager certificateManager, char[] keyStorePassword) throws IOException {

    KeyStore keyStore = certificateManager.getKeyStore();
    try {

      // Existing entry: must be a PrivateKey
      if (keyStore.containsAlias(ACL_SECRET_KEY_ALIAS)) {
        Key existingKey = keyStore.getKey(ACL_SECRET_KEY_ALIAS, keyStorePassword);
        if (existingKey instanceof PrivateKey privateKey) {
          return deriveAesKeyFromPrivateKey(privateKey);
        }
        throw new IOException("Existing ACL key alias is not a PrivateKey");
      }

      // Create a new keypair + self-signed cert for ACL use
      CertificateWithPrivateKey certificateWithPrivateKey =
          generateSelfSignedCertificateSecret(ACL_SECRET_KEY_ALIAS);

      certificateManager.addCertificate(
          ACL_SECRET_KEY_ALIAS, certificateWithPrivateKey.getCertificate());

      certificateManager.addPrivateKey(
          ACL_SECRET_KEY_ALIAS,
          keyStorePassword,
          certificateWithPrivateKey.getPrivateKey(),
          new Certificate[] {certificateWithPrivateKey.getCertificate()});

      certificateManager.saveKeyStore();

      return deriveAesKeyFromPrivateKey(certificateWithPrivateKey.getPrivateKey());
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  private SecretKey deriveAesKeyFromPrivateKey(PrivateKey privateKey) throws GeneralSecurityException {
    byte[] privateKeyBytes = privateKey.getEncoded();

    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    byte[] hash = messageDigest.digest(privateKeyBytes);

    // Use first 32 bytes as AES-256 key
    return new SecretKeySpec(hash, 0, 32, "AES");
  }

}
