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
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.Data;
import lombok.Value;

public class AclAuthorizationProvider implements AuthorizationProvider {
  private static final String ACL_SECRET_KEY_ALIAS = "acl.state.key";

  private final Map<ResourceKey, AccessControlList> accessControlListMap;
  private final Map<Long, Permission> permissions;
  private final AclSaveState saveState;

  public AclAuthorizationProvider() {
    accessControlListMap = null;
    permissions = null;
    saveState = null;
  }

  public AclAuthorizationProvider(String config, Permission[] permission, AclSaveState saveState) {
    this.permissions = new  ConcurrentHashMap<>();
    this.accessControlListMap = new ConcurrentHashMap<>();
    for (Permission permissionPrototype : permission) {
      permissions.put(permissionPrototype.getMask(),  permissionPrototype);
    }
    this.saveState = saveState;
    readState(config);
  }

  public String  getName() {
    return "ACL";
  }

  @Override
  public AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions) throws IOException {
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
      return new AclAuthorizationProvider(aclLoad, permissions, aclSaveState);
    } catch (IOException|GeneralSecurityException e) {
      throw new IOException(e);
    }
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

  private void writeState() {
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

    AuthorizationState authorizationState = gson.fromJson(state, AuthorizationState.class);
    if (authorizationState == null) {
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
