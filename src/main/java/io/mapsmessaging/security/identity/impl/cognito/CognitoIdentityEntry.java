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

package io.mapsmessaging.security.identity.impl.cognito;

import io.mapsmessaging.security.identity.impl.external.JwtIdentityEntry;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import java.io.IOException;
import java.security.GeneralSecurityException;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CognitoIdentityEntry extends JwtIdentityEntry {
  private String uuid;
  private String email;
  private String profile;

  public CognitoIdentityEntry(CognitoAuth cognitoAuth, String username, String uuid) {
    this.username = username;
    this.uuid = uuid;
    this.email = "";
    this.profile = "";
    passwordHasher = new CognitoPasswordHasher(username, cognitoAuth, this);
  }

  @Override
  public PasswordBuffer getPassword() throws GeneralSecurityException, IOException {
    return passwordHasher.getPassword();
  }
}
