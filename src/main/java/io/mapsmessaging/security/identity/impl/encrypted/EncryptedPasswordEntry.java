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

package io.mapsmessaging.security.identity.impl.encrypted;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.ciphers.EncryptedPasswordCipher;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class EncryptedPasswordEntry extends IdentityEntry {

  public EncryptedPasswordEntry(String line, EncryptedPasswordCipher parser) {
    int usernamePos = line.indexOf(":");
    username = line.substring(0, usernamePos);
    line = line.substring(usernamePos + 1);
    password = new PasswordBuffer(line.toCharArray());
    passwordHasher = parser.create(password.getHash());
  }

  public EncryptedPasswordEntry(String username, char[] password, PasswordHandler parser) {
    this.username = username;
    this.password = new PasswordBuffer(password);
    this.passwordHasher = parser;
  }

  @Override
  public PasswordBuffer getPassword() throws GeneralSecurityException, IOException {
    PasswordHandler parser1 = passwordHasher.create(password.getHash());
    return parser1.getPassword();
  }

  @Override
  public PasswordHandler getPasswordHasher() {
    EncryptedPasswordCipher base = (EncryptedPasswordCipher) passwordHasher;
    EncryptedPasswordCipher response = (EncryptedPasswordCipher) passwordHasher.create(password.getHash());
    response.setCertificateManager(base.getCertificateManager());
    return response;
  }
}
