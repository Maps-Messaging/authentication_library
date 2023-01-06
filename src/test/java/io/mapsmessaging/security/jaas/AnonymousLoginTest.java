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

import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import java.util.LinkedHashMap;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AnonymousLoginTest {

  @Test
  void simpleLoginTest() throws LoginException {
    Subject subject = new Subject();
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler("","", "");
    LoginModule module = new AnonymousLoginModule();
    module.initialize(subject, clientCallbackHandler, new LinkedHashMap<>(), new LinkedHashMap<>());
    Assertions.assertTrue(module.login());
    Assertions.assertTrue(subject.getPrincipals().isEmpty());
    Assertions.assertTrue(module.commit());
    Assertions.assertFalse(subject.getPrincipals().isEmpty());
  }

}
