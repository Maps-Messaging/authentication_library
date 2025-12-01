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

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import java.security.Principal;
import java.util.LinkedHashMap;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AnonymousLoginTest {

  @Test
  void simpleLoginTest() {
    Subject subject = new Subject();
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler("", new char[0], "");
    AnonymousLoginModule module = new AnonymousLoginModule();
    module.initialize(subject, clientCallbackHandler, new LinkedHashMap<>(), new LinkedHashMap<>());

    Assertions.assertNotNull( module.getDomain());
    // Test login
    Assertions.assertTrue(module.login());

    // Check subject before commit
    Assertions.assertTrue(subject.getPrincipals().isEmpty());

    // Test commit
    Assertions.assertTrue(module.commit());

    // Check subject after commit
    Assertions.assertFalse(subject.getPrincipals().isEmpty());

    // Ensure the principal is of the correct type
    Principal principal = subject.getPrincipals().iterator().next();
    Assertions.assertInstanceOf(UserPrincipal.class, principal, "Principal is not of type UserPrincipal");

    // Test the functionality of AnonymousPrincipal
    UserPrincipal anonymousPrincipal = (UserPrincipal) principal;
    Assertions.assertNotNull(anonymousPrincipal.getName(), "Principal name should not be null");
    Assertions.assertEquals("anonymous", anonymousPrincipal.getName(), "Principal name does not match");

    // Test the toString method
    String expectedToString = anonymousPrincipal.getName();
    Assertions.assertEquals(expectedToString, anonymousPrincipal.toString(), "toString method does not match expected format");
  }

}
