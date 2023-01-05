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
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
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
  public boolean login() throws LoginException {
    if (identityLookup == null) {
      throw new LoginException("No such identity lookup mechanism loaded");
    }

    // prompt for a username and password
    if (callbackHandler == null) {
      throw new LoginException("Error: no CallbackHandler available to garner authentication information from the user");
    }

    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("user name: ");
    callbacks[1] = new PasswordCallback("password: ", false);

    try {
      callbackHandler.handle(callbacks);
      username = ((NameCallback) callbacks[0]).getName();
      char[] lookup = identityLookup.getPasswordHash(username);
      if (lookup == null) {
        logger.log(NO_SUCH_USER_FOUND, username);
        throw new LoginException("No such user");
      }

      char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
      ((PasswordCallback) callbacks[1]).clearPassword();

      if (tmpPassword == null) {
        // treat a NULL password as an empty password
        tmpPassword = new char[0];
      }
      String rawPassword = new String(tmpPassword);
      String lookupPassword = new String(lookup);
      PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(lookupPassword);

      // This would be done on the client side of this
      byte[] hash = passwordParser.computeHash(rawPassword.getBytes(), passwordParser.getSalt(), passwordParser.getCost());
      if (!Arrays.equals(hash, lookupPassword.getBytes())) {
        throw new LoginException("Invalid password");
      }
      succeeded = true;
      if (debug) {
        logger.log(USER_LOGGED_IN, username);
      }
      return true;
    } catch (IOException ioe) {
      throw new LoginException(ioe.toString());
    } catch (UnsupportedCallbackException uce) {
      throw new LoginException(
          "Error: "
              + uce.getCallback().toString()
              + " not available to garner authentication information "
              + "from the user");
    }
  }

  @Override
  public boolean commit() {
    if (!succeeded) {
      return false;
    } else {
      userPrincipal = new AnonymousPrincipal(username);
      subject.getPrincipals().add(userPrincipal);
      // in any case, clean out state
      password = null;
      return true;
    }
  }
}