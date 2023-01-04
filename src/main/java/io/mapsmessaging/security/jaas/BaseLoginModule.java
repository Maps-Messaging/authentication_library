package io.mapsmessaging.security.jaas;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import java.util.Arrays;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
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
  protected char[] password;

  protected AnonymousPrincipal userPrincipal;

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

  public boolean abort() throws LoginException {
    if (!succeeded) {
      return false;
    } else if (!commitSucceeded) {
      // login succeeded but overall authentication failed
      succeeded = false;
      username = null;
      if (password != null) {
        Arrays.fill(password, ' ');
        password = null;
      }
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
    if (password != null) {
      Arrays.fill(password, ' ');
      password = null;
    }
    userPrincipal = null;
    return true;
  }
}
