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

package io.mapsmessaging.security.identity.impl;

import com.github.javafaker.Faker;
import io.mapsmessaging.security.certificates.BaseCertificateTest;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.identity.impl.encrypted.EncryptedAuth;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.ciphers.EncryptedPasswordCipher;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EncryptedAuthTest extends BaseCertificateTest {

  @Test
  void testBasicFunctions() throws Exception {
    setUp("jks");
    addCert(certificateManager);

    PasswordHandler hasher =
        new EncryptedPasswordCipher(certificateManager, TEST_ALIAS, new String(KEY_PASSWORD));
    EncryptedAuth auth = new EncryptedAuth("encryptedPasswords", "groups", TEST_ALIAS, certificateManager, new String(KEY_PASSWORD));
    Faker faker = new Faker();
    Map<String, String> users = new LinkedHashMap<>();
    for (int x = 0; x < 100; x++) {
      String username = faker.name().username();
      String password = PasswordGenerator.generateSalt(20);
      users.put(username, password);
      auth.createUser(username, password, hasher);
    }

    for (String user : users.keySet()) {
      IdentityEntry entry = auth.findEntry(user);
      String pass = entry.getPassword();
      Assertions.assertEquals(pass, users.get(user));
    }

  }
}
