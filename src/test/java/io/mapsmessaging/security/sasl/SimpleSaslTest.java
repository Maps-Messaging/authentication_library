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

package io.mapsmessaging.security.sasl;

import com.github.javafaker.Faker;
import io.mapsmessaging.security.MapsSecurityProvider;
import io.mapsmessaging.security.access.IdentityAccessManager;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.store.MapFileStore;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.passwords.hashes.sha.Sha1PasswordHasher;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SimpleSaslTest extends BaseSasl {

  private static final Faker faker = new Faker();

  @BeforeAll
  static void register() {
    System.setProperty("sasl.test", "true");
    Security.insertProviderAt(new MapsSecurityProvider(), 1);

    Map<String, Object> cipherConfig = new LinkedHashMap<>();
    Map<String, Object> baseConfig = new LinkedHashMap<>();
    baseConfig.put("certificateStore", cipherConfig);
    baseConfig.put("passwordFile", "htpasswordFile-enc");
    baseConfig.put("groupFile", "htgroupFile-enc");
    baseConfig.put("passwordHandler", "EncryptedPasswordCipher");

    cipherConfig.put("alias", "alias");
    cipherConfig.put("privateKey.passphrase", "8 5tr0ng pr1v8t3 k3y p855w0rd!@#$%");
    cipherConfig.put("privateKey.name", "alias");
    cipherConfig.put("type", "JKS");
    cipherConfig.put("path", "test.jks");
    cipherConfig.put("passphrase", "8 5Tr0Ng C3rt!f1c8t3 P855sw0rd!!!!");

    File userFile = new File("userMap");
    userFile.delete();
    File groupFile = new File("groupMap");
    groupFile.delete();

    MapFileStore<UserIdMap> users = new MapFileStore<>("userMap");
    MapFileStore<GroupIdMap> groups = new MapFileStore<>("groupMap");

    identityAccessManager = new IdentityAccessManager("Encrypted-Auth", baseConfig, users, groups);
    IdentityLookupFactory.getInstance()
        .registerSiteIdentityLookup("Encrypted-Auth", identityAccessManager.getIdentityLookup());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "PLAIN",
        "DIGEST-MD5",
        "CRAM-MD5",
        "SCRAM-SHA-256",
        "SCRAM-SHA-512",
        "SCRAM-SHA3-256",
        "SCRAM-SHA3-512"
      })
  void validateSaslMechanisms(String mechanism) throws IOException, GeneralSecurityException {
    testMechanism(mechanism, faker.backToTheFuture().character(), faker.backToTheFuture().quote().toCharArray());
  }

  void simpleWrongPasswordTest(String mechanism) {
    Sha1PasswordHasher passwordParser = new Sha1PasswordHasher();
    char[] password =
        passwordParser.transformPassword(
            "This is a wrong password".toCharArray(), null, 0);
    Assertions.assertThrowsExactly(SaslException.class, () -> testMechanism(mechanism, "fred2@google.com", password));
  }

  void testMechanism(String mechanism, String user, char[] password)
      throws IOException, GeneralSecurityException {
    user = user.replaceAll(" ", "_");
    if (identityAccessManager.getUserManagement().getUser(user) != null) {
      identityAccessManager.getUserManagement().deleteUser(user);
    }
    identityAccessManager.getUserManagement().createUser(user, password);
    SaslTester saslTester = new SaslTester();
    saslTester.testMechanism(identityAccessManager.getIdentityLookup(), mechanism, user, password);
    identityAccessManager.getUserManagement().deleteUser(user);
  }

}
