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

package io.mapsmessaging.security;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import java.util.UUID;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Test;

class SubjectHelperTest {

  @Test
  void testGetUsername() {
    Subject subject = new Subject();
    UserPrincipal userPrincipal = new UserPrincipal("testUser");
    subject.getPrincipals().add(userPrincipal);

    String username = SubjectHelper.getUsername(subject);
    assertEquals("testUser", username, "Username should match the name in UserPrincipal");
  }

  @Test
  void testGetRemoteHost() {
    Subject subject = new Subject();
    RemoteHostPrincipal remoteHostPrincipal = new RemoteHostPrincipal("127.0.0.1");
    subject.getPrincipals().add(remoteHostPrincipal);

    String remoteHost = SubjectHelper.getRemoteHost(subject);
    assertEquals(
        "127.0.0.1", remoteHost, "Remote host should match the name in RemoteHostPrincipal");
  }

  @Test
  void testGetAuthDomain() {
    Subject subject = new Subject();
    AuthHandlerPrincipal authHandlerPrincipal = new AuthHandlerPrincipal("testDomain");
    subject.getPrincipals().add(authHandlerPrincipal);

    String authDomain = SubjectHelper.getAuthDomain(subject);
    assertEquals(
        "testDomain", authDomain, "Auth domain should match the name in AuthHandlerPrincipal");
  }

  @Test
  void testGetUniqueId() {
    Subject subject = new Subject();
    UUID testUUID = UUID.randomUUID();
    UniqueIdentifierPrincipal uniqueIdentifierPrincipal = new UniqueIdentifierPrincipal(testUUID);
    subject.getPrincipals().add(uniqueIdentifierPrincipal);

    UUID uniqueId = SubjectHelper.getUniqueId(subject);
    assertEquals(
        testUUID, uniqueId, "Unique ID should match the UUID in UniqueIdentifierPrincipal");
  }
}

