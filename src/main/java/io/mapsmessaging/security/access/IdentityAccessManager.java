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

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import io.mapsmessaging.security.access.monitor.AuthenticationMonitor;
import io.mapsmessaging.security.access.monitor.AuthenticationMonitorConfig;
import io.mapsmessaging.security.authorisation.*;
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
      ResourceTraversalFactory traversalFactory,
      AuthenticationMonitorConfig authMonitorConfig,
      Permission[]  permissions) throws IOException {
    identityLookup = IdentityLookupFactory.getInstance().get(identity, config);


    if(config.containsKey("authorisationProvider")) {
      String authorisationProvider = config.get("authorisationProvider").toString();
      authorizationProvider = AuthorizationProviderFactory.getInstance().get( authorisationProvider, config, permissions, traversalFactory);
    }
    else{
      authorizationProvider = new OpenAuthorizationProvider();
    }

    GroupMapManagement groupMapManagement = new GroupMapManagement(groupStore);
    UserMapManagement userMapManagement = new UserMapManagement(userStore);

    AuthenticationMonitor authenticationMonitor = new AuthenticationMonitor(authMonitorConfig);
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
    userManagement = new UserManagement(identityLookup, userMapManagement, groupManagement, passwordHandler, authorizationProvider, authenticationMonitor);

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

  public boolean validateUser(String username, char[] passwordHash, AuthContext context) throws IOException{
    return userManagement.validateUser(username, passwordHash, context);
  }

  public void setAsSystemIdentityLookup(){
    IdentityLookupFactory.getInstance().registerSiteIdentityLookup("system", identityLookup);
  }
}
