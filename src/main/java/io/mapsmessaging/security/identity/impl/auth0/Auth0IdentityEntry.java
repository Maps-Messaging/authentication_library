/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.identity.impl.auth0;

import static io.mapsmessaging.security.logging.AuthLogMessages.AUTH0_PASSWORD_FAILURE;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.impl.external.JwtIdentityEntry;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class Auth0IdentityEntry extends JwtIdentityEntry {

  private static final Logger logger = LoggerFactory.getLogger(Auth0IdentityEntry.class);

  public Auth0IdentityEntry(Auth0Auth auth0Auth, String username) {
    super();
    this.username = username;
    passwordHasher = new Auth0PasswordHasher(username, auth0Auth, this);
  }

  @Override
  public PasswordBuffer getPassword() {
    try {
      return passwordHasher.getPassword();
    } catch (GeneralSecurityException | IOException e) {
      logger.log(AUTH0_PASSWORD_FAILURE, username, e);
      return null;
    }
  }
}
