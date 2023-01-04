package io.mapsmessaging.security.jaas;

import io.mapsmessaging.security.auth.PasswordParser;
import io.mapsmessaging.security.auth.PasswordParserFactory;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.sasl.impl.htpasswd.HtPasswd;
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
import javax.security.auth.spi.LoginModule;

public class HtPasswordLoginModule implements LoginModule {

  protected final Logger logger = LoggerFactory.getLogger(HtPasswordLoginModule.class);
  protected HtPasswd htPasswd;
  protected Subject subject;
  protected CallbackHandler callbackHandler;

  protected String username;
  protected AnonymousPrincipal userPrincipal;

  // configurable option
  protected boolean debug = false;

  protected boolean succeeded = false;
  protected boolean commitSucceeded = false;

  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {

    this.subject = subject;
    this.callbackHandler = callbackHandler;

    // initialize any configured options
    debug = "true".equalsIgnoreCase((String) options.get("debug"));
    htPasswd = new HtPasswd(options.get("htpasswordFile").toString());
  }

  @Override
  public boolean login() throws LoginException {

    // prompt for a user name and password
    if (callbackHandler == null) {
      throw new LoginException("Error: no CallbackHandler available to garner authentication information from the user");
    }

    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("user name: ");
    callbacks[1] = new PasswordCallback("password: ", false);

    try {
      callbackHandler.handle(callbacks);
      username = ((NameCallback) callbacks[0]).getName();
      char[] lookup = htPasswd.getPasswordHash(username);
      if(lookup == null){
        throw new LoginException("No such user");
      }
      PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(new String(lookup));

      char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();
      ((PasswordCallback) callbacks[1]).clearPassword();

      if (tmpPassword == null) {
        // treat a NULL password as an empty password
        tmpPassword = new char[0];
      }
      String rawPassword = new String(tmpPassword);
      byte[] hash = passwordParser.computeHash(rawPassword.getBytes(), passwordParser.getSalt(), passwordParser.getCost());
      if (!Arrays.equals(hash, passwordParser.getPassword())) {
        throw new LoginException("Invalid password");
      }
      succeeded = true;
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

      commitSucceeded = true;
      return true;
    }
  }
  public boolean abort() throws LoginException {
    if (!succeeded) {
      return false;
    } else if (!commitSucceeded) {
      // login succeeded but overall authentication failed
      succeeded = false;
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
    userPrincipal = null;
    return true;
  }
}