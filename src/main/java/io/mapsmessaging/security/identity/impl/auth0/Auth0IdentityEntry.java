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

package io.mapsmessaging.security.identity.impl.auth0;

import io.mapsmessaging.security.identity.impl.external.JwtIdentityEntry;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class Auth0IdentityEntry extends JwtIdentityEntry {

  public Auth0IdentityEntry(Auth0Auth auth0Auth, String username) {
    super();
    this.username = username;
    passwordHasher = new Auth0PasswordHasher(username, auth0Auth, this);
  }

  @Override
  public String getPassword() {
    try {
      return new String(passwordHasher.getPassword());
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
