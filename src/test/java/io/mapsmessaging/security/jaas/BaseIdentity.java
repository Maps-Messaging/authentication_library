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

  protected  Subject subject;
  abstract Map<String, String> getOptions();

  abstract String getUser();

  abstract char[] getPassword();

  String getInvalidUser() {
    return "no such user";
  }

  char[] getInvalidPassword() {
    return "doesn't really matter".toCharArray();
  }

  LoginModule createLoginModule(CallbackHandler callbackHandler) {
    return createLoginModule(callbackHandler, getOptions());
  }

  LoginModule createLoginModule(CallbackHandler callbackHandler, Map<String, ?> options) {
    LoginModule module = new IdentityLoginModule();
    subject = new Subject();
    module.initialize(subject, callbackHandler, new LinkedHashMap<>(), options);
    return module;
  }


  @Test
  void noPasswordFileTestTest()  {
    Map<String,String> options = getOptions();
    options.put("passwordFile", "NoSuchFile");
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler, options);
    Assertions.assertThrowsExactly(LoginException.class, module::login);
  }


  @Test
  void simpleLoginTest() throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertTrue(module.login());
    Assertions.assertTrue(subject.getPrincipals().isEmpty());
    Assertions.assertTrue(module.commit());
    validateSubject(subject);
  }



  @Test
  void simpleLoginValidationTest() {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertNotNull(module);
    Assertions.assertInstanceOf(BaseLoginModule.class, module);
    Assertions.assertNotNull(((BaseLoginModule)module).getDomain());
  }

  protected void validateSubject(Subject subject) {
    Assertions.assertFalse(subject.getPrincipals().isEmpty());
  }

  @Test
  void simpleAbortLoginTest() throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertTrue(module.login());
    Assertions.assertTrue(subject.getPrincipals().isEmpty());
    Assertions.assertTrue(module.abort());
    Assertions.assertTrue(subject.getPrincipals().isEmpty());
  }

  @Test
  void simpleModuleTest() throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertTrue(module.login());
    Assertions.assertTrue(module.commit());
    Assertions.assertTrue(module.logout());
  }

  @Test
  void simpleFailedLoginTest() {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getInvalidUser(), getPassword(), "");
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertThrowsExactly(LoginException.class, module::login);

    clientCallbackHandler = new ClientCallbackHandler(getUser(), getInvalidPassword(), "");
    LoginModule module1 = createLoginModule(clientCallbackHandler);
    Assertions.assertThrowsExactly(LoginException.class, module1::login);

  }

}
