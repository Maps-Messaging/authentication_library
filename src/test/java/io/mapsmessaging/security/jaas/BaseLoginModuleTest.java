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

import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;

public abstract class BaseLoginModuleTest {


  @BeforeAll
  static void setJaasConfig(){
    System.setProperty("java.security.auth.login.config","src/test/resources/jaasAuth.config");
  }

  abstract String getUser();

  abstract char[] getPassword();


  void testLoad(String jaasConfigName) throws LoginException {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), getPassword(), "");
    LoginContext loginContext = new LoginContext(jaasConfigName, clientCallbackHandler);
    Assertions.assertNotNull(loginContext);
    loginContext.login();

    // Access the authenticated Subject
    Subject subject = loginContext.getSubject();

    // Perform actions with the authenticated Subject
    // ...

    // Logout the Subject
    loginContext.logout();
  }
}
