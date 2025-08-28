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

import static io.mapsmessaging.security.logging.AuthLogMessages.USER_LOGGED_OUT;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

public abstract class BaseLoginModule implements LoginModule {

  protected final Logger logger = LoggerFactory.getLogger(BaseLoginModule.class);
  protected Subject subject;
  protected CallbackHandler callbackHandler;

  // configurable option
  protected boolean debug = false;

  protected boolean succeeded = false;
  protected boolean commitSucceeded = false;

  protected String username;

  protected Principal userPrincipal;

  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {

    this.subject = subject;
    this.callbackHandler = callbackHandler;

    // initialize any configured options
    debug = "true".equalsIgnoreCase((String) options.get("debug"));
  }

  protected abstract String getDomain();

  protected abstract boolean validate(String username, char[] password) throws LoginException;

  @Override
  public boolean login() throws LoginException {

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
      char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
      if (tmpPassword == null) {
        // treat a NULL password as an empty password
        tmpPassword = new char[0];
      }
      char[] password = new char[tmpPassword.length];
      System.arraycopy(tmpPassword, 0, password, 0, tmpPassword.length);
      userPrincipal = new UserPrincipal(username);
      if (!validate(username, password)) {
        throw new LoginException("Username or password is invalid");
      }
      ((PasswordCallback) callbacks[1]).clearPassword();
    } catch (IOException ioe) {
      throw new LoginException(ioe.toString());
    } catch (UnsupportedCallbackException uce) {
      throw new LoginException(
          "Error: "
              + uce.getCallback().toString()
              + " not available to garner authentication information "
              + "from the user");
    }
    succeeded = true;
    return true;
  }

  public boolean abort() throws LoginException {
    subject.getPrincipals().clear();
    subject.getPrivateCredentials().clear();
    subject.getPublicCredentials().clear();
    if (!succeeded) {
      return false;
    } else if (!commitSucceeded) {
      // login succeeded but overall authentication failed
      succeeded = false;
      username = null;
      userPrincipal = null;
    } else {
      logout();
    }
    return true;
  }

  public boolean logout() throws LoginException {
    if (subject != null && userPrincipal != null) {
      subject.getPrincipals().remove(userPrincipal);
    }
    succeeded = commitSucceeded;
    username = null;
    userPrincipal = null;
    if (debug) {
      logger.log(USER_LOGGED_OUT, username);
    }
    return true;
  }

  @Override
  public boolean commit() {
    if (!succeeded) {
      subject.getPrincipals().clear();
      subject.getPrivateCredentials().clear();
      subject.getPublicCredentials().clear();
      return false;
    } else {
      Set<Principal> principalSet = subject.getPrincipals();
      principalSet.add(userPrincipal);
      commitSucceeded = true;
      return true;
    }
  }
}
