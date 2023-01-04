package io.mapsmessaging.security.jaas;


import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

public class SSLCertificateLoginModule extends BaseLoginModule {

  private Principal sslPrincipal;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    sslPrincipal = null;
  }

  @Override
  public boolean login() throws LoginException {

    // prompt for a username and password
    if (callbackHandler == null) {
      throw new LoginException(
          "Error: no CallbackHandler available to garner authentication information from the user");
    }

    Callback[] callbacks = new Callback[3];
    callbacks[0] = new NameCallback("user name: ");
    callbacks[1] = new PrincipalCallback();
    callbacks[2] = new PasswordCallback("password: ", false);

    try {
      callbackHandler.handle(callbacks);
      username = ((NameCallback) callbacks[0]).getName();
      sslPrincipal = ((PrincipalCallback) callbacks[1]).getPrincipal();
      char[] tmpPassword = ((PasswordCallback) callbacks[2]).getPassword();
      if (tmpPassword == null) {
        // treat a NULL password as an empty password
        tmpPassword = new char[0];
      }
      password = new char[tmpPassword.length];
      System.arraycopy(tmpPassword, 0, password, 0, tmpPassword.length);
      ((PasswordCallback) callbacks[2]).clearPassword();
    } catch (IOException ioe) {
      throw new LoginException(ioe.toString());
    } catch (UnsupportedCallbackException uce) {
      throw new LoginException(
          "Error: "
              + uce.getCallback().toString()
              + " not available to garner authentication information from the user");
    }

    succeeded = true;
    return true;
  }

  @Override
  public boolean commit() {
    if (!succeeded) {
      return false;
    } else {
      subject.getPrincipals().add(sslPrincipal);
      // in any case, clean out state
      if (password != null) {
        Arrays.fill(password, ' ');
        password = null;
      }
      sslPrincipal = null;
      commitSucceeded = true;
      return true;
    }
  }

  @Override
  public boolean abort() throws LoginException {
    sslPrincipal = null;
    return super.abort();
  }
}
