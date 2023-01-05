package io.mapsmessaging.security.jaas;

import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public abstract class BaseIdentity {

  abstract Map<String, String> getOptions();

  abstract String getUser();

  abstract String getPassword();

  String getInvalidUser() {
    return "no such user";
  }

  String getInvalidPassword() {
    return "doesn't really matter";
  }

  LoginModule createLoginModule(CallbackHandler callbackHandler) {
    LoginModule module = new IdentityLoginModule();
    Subject subject = new Subject();
    module.initialize(subject, callbackHandler, new LinkedHashMap<>(), getOptions());
    return module;
  }


  @Test
  void simpleLoginTest() throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertTrue(module.login());
  }

  @Test
  void simpleModuleTest() throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertTrue(module.login());
    Assertions.assertTrue(module.logout());
  }

  @Test
  void simpleFailedLoginTest() throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getInvalidUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertThrowsExactly(LoginException.class, () -> module.login());

    clientCallbackHandler = new ClientCallbackHandler(getUser(), getInvalidPassword(), "");
    LoginModule module1 = createLoginModule(clientCallbackHandler);
    Assertions.assertThrowsExactly(LoginException.class, () -> module1.login());

  }

}
