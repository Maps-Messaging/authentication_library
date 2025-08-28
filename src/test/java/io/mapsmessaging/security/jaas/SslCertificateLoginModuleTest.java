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

import static org.junit.jupiter.api.Assertions.*;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import org.junit.jupiter.api.Test;

class SSLCertificateLoginModuleTest {

  @Test
  void testLoginAndCommit() throws LoginException {
    SSLCertificateLoginModule loginModule = new SSLCertificateLoginModule();
    Subject subject = new Subject();
    CallbackHandler callbackHandler = createCallbackHandler("testUser", new UserPrincipal("testUser"));

    loginModule.initialize(subject, callbackHandler, null, new LinkedHashMap<>());
    assertTrue(loginModule.login(), "Login should succeed");

    assertEquals("cert", loginModule.getDomain());

    assertTrue(loginModule.commit(), "Commit should succeed");
    assertTrue(subject.getPrincipals().contains(new UserPrincipal("testUser")), "Subject should contain UserPrincipal with 'testUser'");
    List<AuthHandlerPrincipal> authHandlerPrincipals = new ArrayList<>(subject.getPrincipals(AuthHandlerPrincipal.class));
    assertNotNull(authHandlerPrincipals);
    assertTrue(loginModule.validate("", new char[0]));
    assertEquals(1, authHandlerPrincipals.size());
    assertEquals("SSLCertificate", authHandlerPrincipals.get(0).getName());
  }

  private CallbackHandler createCallbackHandler(String username, Principal userPrincipal) {
    return callbacks -> {
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback) {
          ((NameCallback) callback).setName(username);
        } else if (callback instanceof PrincipalCallback) {
          ((PrincipalCallback) callback).setPrincipal(userPrincipal);
        }
      }
    };
  }

  // Additional tests could include scenarios where callbackHandler is null, IOException is thrown, etc.
}