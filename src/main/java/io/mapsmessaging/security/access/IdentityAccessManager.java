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

package io.mapsmessaging.security.access;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import io.mapsmessaging.security.authorisation.*;
import io.mapsmessaging.security.authorisation.impl.acl.AclAuthorizationProvider;
import io.mapsmessaging.security.authorisation.impl.acl.AccessControlList;
import io.mapsmessaging.security.authorisation.impl.open.OpenAuthorizationProvider;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.impl.encrypted.EncryptedAuth;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.ciphers.EncryptedPasswordCipher;
import java.io.IOException;
import java.util.*;
import javax.security.auth.Subject;
import lombok.Getter;

@Getter
public class IdentityAccessManager {

  private final IdentityLookup identityLookup;
  private final UserManagement userManagement;
  private final GroupManagement groupManagement;
  private final AuthorizationProvider authorizationProvider;

  public IdentityAccessManager(
      String identity,
      Map<String, Object> config,
      MapStore<UserIdMap> userStore,
      MapStore<GroupIdMap> groupStore,
      Permission[]  permissions) throws IOException {
    identityLookup = IdentityLookupFactory.getInstance().get(identity, config);


    if(config.containsKey("authorization") && config.get("authorization") instanceof Map auth) {
      String name = auth.get("name").toString();
      authorizationProvider = AuthorizationProviderFactory.getInstance().get( name, auth, permissions);
    }
    else{
      authorizationProvider = new OpenAuthorizationProvider();
    }


    GroupMapManagement groupMapManagement = new GroupMapManagement(groupStore);
    UserMapManagement userMapManagement = new UserMapManagement(userStore);

    PasswordHandler passwordHandler;
    String handlerName = (String) config.get("passwordHandler");
    if (handlerName == null || handlerName.isEmpty()) {
      handlerName = "Pbkdf2Sha512PasswordHasher";
    }
    PasswordHandler baseHandler = PasswordHandlerFactory.getInstance().getByClassName(handlerName);
    if (baseHandler instanceof EncryptedPasswordCipher && identityLookup instanceof EncryptedAuth) {
      passwordHandler = ((EncryptedAuth) identityLookup).getPasswordHandler();
    } else {
      passwordHandler = baseHandler;
    }
    groupManagement = new GroupManagement(identityLookup, userMapManagement, groupMapManagement, authorizationProvider);
    userManagement = new UserManagement(identityLookup, userMapManagement, groupManagement, passwordHandler, authorizationProvider);

    userMapManagement.save();
    groupMapManagement.save();
  }

  public Subject updateSubject(Subject subject) {
    String username = SubjectHelper.getUsername(subject);
    IdentityEntry identityEntry = userManagement.updateSubject(subject, username);
    if (identityEntry != null) {
      subject = groupManagement.updateSubject(subject, identityEntry);
    }
    else{
      subject = null;
    }
    return subject;
  }

  public boolean validateUser(String username, char[] passwordHash) throws IOException{
    return userManagement.validateUser(username, passwordHash);
  }

  public boolean canAccess(Identity identity, Permission permission, ProtectedResource resource) {
    return authorizationProvider.canAccess(identity, permission, resource);
  }

  public void grant(Identity identity, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forIdentity(identity);
    authorizationProvider.grantAccess(grantee, permission, resource);
  }

  public void grant(Group group, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forGroup(group);
    authorizationProvider.grantAccess(grantee, permission, resource);
  }

  public void revoke(Identity identity, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forIdentity(identity);
    authorizationProvider.revokeAccess(grantee, permission, resource);
  }

  public void revoke(Group group, Permission permission, ProtectedResource resource) {
    Grantee grantee = Grantee.forGroup(group);
    authorizationProvider.revokeAccess(grantee, permission, resource);
  }

  public void setAsSystemIdentityLookup(){
    IdentityLookupFactory.getInstance().registerSiteIdentityLookup("system", identityLookup);
  }
}
