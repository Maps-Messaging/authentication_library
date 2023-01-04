package io.mapsmessaging.security.jaas;

import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.impl.htpasswd.HtPasswd;
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

public class HtPasswordLoginModule extends BaseLoginModule {

  private IdentityLookup identityLookup;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    identityLookup = new HtPasswd(options.get("htPasswordFile").toString());
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
      char[] lookup = identityLookup.getPasswordHash(username);
      if(lookup == null){
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