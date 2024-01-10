/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import static io.mapsmessaging.security.logging.AuthLogMessages.USER_LOGGED_IN;

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
      identityLookup = IdentityLookupFactory.getInstance().get(identityLookupName, options);
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

    PasswordParser passwordParser = identityEntry.getPasswordParser();
    if (passwordParser == null) {
      passwordParser = PasswordParserFactory.getInstance().parse(identityEntry.getPassword());
    }
    String rawPassword = new String(password);
    byte[] hash = passwordParser.computeHash(rawPassword.getBytes(StandardCharsets.UTF_8), passwordParser.getSalt(), passwordParser.getCost());
    if (!Arrays.equals(hash, identityEntry.getPassword().getBytes(StandardCharsets.UTF_8))) {
      throw new LoginException("Invalid password");
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
