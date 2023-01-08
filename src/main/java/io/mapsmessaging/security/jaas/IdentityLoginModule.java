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

import static io.mapsmessaging.security.logging.AuthLogMessages.NO_SUCH_USER_FOUND;
import static io.mapsmessaging.security.logging.AuthLogMessages.USER_LOGGED_IN;

import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import java.util.Arrays;
import java.util.Map;
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
    if (options.containsKey("identityName")) {
      String identityLookupName = options.get("identityName").toString();
      identityLookup = IdentityLookupFactory.getInstance().get(identityLookupName, options);
    }
  }

  @Override
  protected boolean validate(String username, char[] password) throws LoginException {
    try {
      char[] lookup = identityLookup.getPasswordHash(username);
      if (lookup == null) {
        logger.log(NO_SUCH_USER_FOUND, username);
        throw new LoginException("No such user");
      }
      String lookupPassword = new String(lookup);
      PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(lookupPassword);

      String rawPassword = new String(password);
      // This would be done on the client side of this
      byte[] hash = passwordParser.computeHash(rawPassword.getBytes(), passwordParser.getSalt(), passwordParser.getCost());
      if (!Arrays.equals(hash, lookupPassword.getBytes())) {
        throw new LoginException("Invalid password");
      }
      userPrincipal = new AnonymousPrincipal(username);
      succeeded = true;
      if (debug) {
        logger.log(USER_LOGGED_IN, username);
      }
      return true;
    } catch (NoSuchUserFoundException e) {
      LoginException loginException = new LoginException("Login failed");
      loginException.initCause(e);
      throw loginException;
    }
  }
}