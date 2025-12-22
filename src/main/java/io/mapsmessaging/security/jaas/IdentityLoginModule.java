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

package io.mapsmessaging.security.jaas;

import static io.mapsmessaging.security.logging.AuthLogMessages.USER_LOGGED_IN;

import io.mapsmessaging.security.access.AuthContext;
import io.mapsmessaging.security.access.monitor.AuthenticationMonitor;
import io.mapsmessaging.security.access.monitor.AuthenticationMonitorConfig;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

public class IdentityLoginModule extends BaseLoginModule {

  private IdentityLookup identityLookup = null;
  private AuthenticationMonitor authenticationMonitor = null;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    if (options.containsKey("siteWide")) {
      String siteWide = options.get("siteWide").toString();
      identityLookup = IdentityLookupFactory.getInstance().getSiteWide(siteWide);
    } else if (options.containsKey("identityName")) {
      String identityLookupName = options.get("identityName").toString();
      identityLookup = IdentityLookupFactory.getInstance().get(identityLookupName, (Map<String, Object>) options);
    }
    authenticationMonitor = IdentityLookupFactory.getInstance().getAuthenticationMonitor();
    if(authenticationMonitor == null){
      authenticationMonitor = new AuthenticationMonitor(new AuthenticationMonitorConfig());
      IdentityLookupFactory.getInstance().setAuthenticationMonitor(authenticationMonitor);
    }
  }

  @Override
  protected String getDomain() {
    return identityLookup.getDomain();
  }

  @Override
  protected boolean validate(String username, char[] password, AuthContext context) throws LoginException {
    if (validateUser(username, password, context)) {
      succeeded = true;
      if (debug) {
        logger.log(USER_LOGGED_IN, username);
      }
      return true;
    }
    return false;
  }

  private boolean validateUser(String username, char[] password, AuthContext context) throws LoginException {

    String ipAddress = context.ipAddress();
    // Fast fail if currently locked
    if (authenticationMonitor.isLocked(username)) {
      return false;
    }

    IdentityEntry entry = identityLookup.findEntry(username);
    boolean success = false;
    try {
      if (entry != null) {
        success = entry.getPasswordHasher().matches(password);
      }
    } catch (IOException|GeneralSecurityException e) {
      authenticationMonitor.recordFailure(username, ipAddress);
      throw new LoginException(e.getMessage());
    }

    if (success) {
      authenticationMonitor.recordSuccess(username, ipAddress);
      return true;
    }
    authenticationMonitor.recordFailure(username, ipAddress);
    return false;
  }

  @Override
  public boolean commit() {
    if (!succeeded) {
      return false;
    } else {
      IdentityEntry identityEntry = identityLookup.findEntry(username);
      Subject subject1 = identityEntry.getSubject();
      Set<Principal> principalSet = subject.getPrincipals();
      principalSet.addAll(subject1.getPrincipals());
      principalSet.add(new AuthHandlerPrincipal("Identity:" + identityLookup.getName()));
      principalSet.add(userPrincipal);

      subject.getPrivateCredentials().addAll(subject1.getPrivateCredentials());
      subject.getPublicCredentials().addAll(subject1.getPublicCredentials());
      commitSucceeded = true;
      return true;
    }
  }
}
