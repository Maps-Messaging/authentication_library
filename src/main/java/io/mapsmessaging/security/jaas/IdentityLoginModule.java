/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.jaas;

import static io.mapsmessaging.security.logging.AuthLogMessages.USER_LOGGED_IN;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import io.mapsmessaging.security.passwords.PasswordCipher;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.hashes.plain.PlainPasswordHasher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

public class IdentityLoginModule extends BaseLoginModule {

  private IdentityLookup identityLookup = null;

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
  }

  @Override
  protected String getDomain() {
    return identityLookup.getDomain();
  }

  @Override
  protected boolean validate(String username, char[] password) throws LoginException {
    IdentityEntry identityEntry = identityLookup.findEntry(username);
    if (identityEntry == null) {
      throw new LoginException("Login failed: No such user");
    }
    char[] actualPassword;
    char[] remotePassword = password;

    try {
      PasswordHandler passwordHasher = identityEntry.getPasswordHasher();
      if (passwordHasher == null) {
        passwordHasher = PasswordHandlerFactory.getInstance().parse(identityEntry.getPassword());
      }

      if (passwordHasher instanceof PasswordCipher || passwordHasher instanceof PlainPasswordHasher) {
        actualPassword = passwordHasher.getPassword();
      } else {
        remotePassword = passwordHasher.transformPassword(remotePassword, passwordHasher.getSalt(), passwordHasher.getCost());
        actualPassword = passwordHasher.getFullPasswordHash();
      }
      boolean result = Arrays.equals(actualPassword, remotePassword);
      if(actualPassword != null) Arrays.fill(actualPassword, (char) 0x0);
      if(remotePassword != null) Arrays.fill(remotePassword, (char) 0x0);
      if (!result) {
        throw new LoginException("Invalid password");
      }
    } catch (IOException | GeneralSecurityException error) {
      LoginException lg = new LoginException("Error raised while processing");
      lg.initCause(error);
      throw lg;
    }

    succeeded = true;
    if (debug) {
      logger.log(USER_LOGGED_IN, username);
    }
    return true;
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
