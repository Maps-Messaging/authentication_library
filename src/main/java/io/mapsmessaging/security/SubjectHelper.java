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

package io.mapsmessaging.security;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import java.util.UUID;
import javax.security.auth.Subject;

public class SubjectHelper {

  public static String getUsername(Subject subject) {
    return subject.getPrincipals(UserPrincipal.class).stream()
        .findFirst()
        .map(UserPrincipal::getName)
        .orElse(null);
  }

  public static String getRemoteHost(Subject subject) {
    return subject.getPrincipals(RemoteHostPrincipal.class).stream()
        .findFirst()
        .map(RemoteHostPrincipal::getName)
        .orElse(null);
  }

  public static String getAuthDomain(Subject subject) {
    return subject.getPrincipals(AuthHandlerPrincipal.class).stream()
        .findFirst()
        .map(AuthHandlerPrincipal::getName)
        .orElse(null);
  }

  public static UUID getUniqueId(Subject subject) {
    return subject.getPrincipals(UniqueIdentifierPrincipal.class).stream()
        .findFirst()
        .map(UniqueIdentifierPrincipal::getAuthId)
        .orElse(null);
  }

  private SubjectHelper() {}
}
