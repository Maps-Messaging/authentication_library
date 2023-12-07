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

package io.mapsmessaging.security.identity.impl.auth0;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.principals.JwtPrincipal;
import io.mapsmessaging.security.identity.principals.TokenPrincipal;
import java.security.Principal;
import java.util.Set;

public class Auth0IdentityEntry extends IdentityEntry {

  public Auth0IdentityEntry(Auth0Auth auth0Auth, String username) {
    super();
    this.username = username;
    passwordParser = new Auth0PasswordParser(username, auth0Auth);
  }

  @Override
  public String getPassword() {
    return new String(passwordParser.getPassword());
  }

  @Override
  protected Set<Principal> getPrincipals() {
    Set<Principal> principals = super.getPrincipals();
    if (passwordParser instanceof Auth0PasswordParser) {
      Auth0PasswordParser auth0PasswordParser = (Auth0PasswordParser) passwordParser;
      if (auth0PasswordParser.getToken() != null) {
        principals.add(new TokenPrincipal(auth0PasswordParser.getToken().getAccessToken()));
      }
      if (auth0PasswordParser.getJwt() != null) {
        principals.add(new JwtPrincipal(auth0PasswordParser.getJwt()));
      }
    }
    return principals;
  }
}
