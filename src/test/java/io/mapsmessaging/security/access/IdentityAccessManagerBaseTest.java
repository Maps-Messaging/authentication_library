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

package io.mapsmessaging.security.access;

import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.github.javafaker.Faker;
import io.mapsmessaging.security.MapsSecurityProvider;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.store.MapFileStore;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.jaas.IdentityLoginModule;
import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import io.mapsmessaging.security.sasl.SaslTester;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class IdentityAccessManagerBaseTest extends BaseSecurityTest {
  @BeforeAll
  static void register() {
    System.setProperty("sasl.test", "true");
    Security.insertProviderAt(new MapsSecurityProvider(), 1);
  }

  private static List<Arguments> configurations() {
    List<Arguments> arguments = new ArrayList<>();
    Map<String, Object> apacheConfig = new LinkedHashMap<>();
    apacheConfig.put("passwordFile", "htpasswordFile");
    apacheConfig.put("groupFile", "htgroupFile");
    apacheConfig.put("passwordHander", "PlainPasswordHasher");

    Map<String, Object> cipherConfig = new LinkedHashMap<>();
    Map<String, Object> baseConfig = new LinkedHashMap<>();
    baseConfig.put("certificateStore", cipherConfig);
    baseConfig.put("passwordFile", "htpasswordFile-enc");
    baseConfig.put("groupFile", "htgroupFile-enc");
    baseConfig.put("passwordHander", "EncryptedPasswordCipher");

    cipherConfig.put("alias", "alias");
    cipherConfig.put("privateKey.passphrase", "8 5tr0ng pr1v8t3 k3y p855w0rd!@#$%");
    cipherConfig.put("privateKey.name", "alias");
    cipherConfig.put("type", "JKS");
    cipherConfig.put("path", "test.jks");
    cipherConfig.put("passphrase", "8 5Tr0Ng C3rt!f1c8t3 P855sw0rd!!!!");

    String[] mechanisms = new String[] {"SCRAM-SHA-512", "SCRAM-SHA-256", "DIGEST-MD5", "CRAM-MD5"};
    for (String sasl : mechanisms) {
      arguments.add(arguments("Apache-Basic-Auth", apacheConfig, sasl));
      arguments.add(arguments("Encrypted-Auth", baseConfig, sasl));
    }
    return arguments;
  }

  @ParameterizedTest
  @MethodSource("configurations")
  void testUserManagement(String auth, Map<String, ?> config, String mechanism)
      throws IOException, GeneralSecurityException {
    File userFile = new File("userMap");
    userFile.delete();
    File groupFile = new File("groupMap");
    groupFile.delete();

    MapFileStore<UserIdMap> users = new MapFileStore<>("userMap");
    MapFileStore<GroupIdMap> groups = new MapFileStore<>("groupMap");

    IdentityAccessManager identityAccessManager = new IdentityAccessManager(auth, config, users, groups);
    IdentityLookupFactory.getInstance().registerSiteIdentityLookup(auth, identityAccessManager.getIdentityLookup());

    for (UserIdMap userIdMap : identityAccessManager.getAllUsers()) {
      identityAccessManager.deleteUser(userIdMap.getUsername());
    }
    for (GroupIdMap groupIdMap : identityAccessManager.getAllGroups()) {
      identityAccessManager.deleteGroup(groupIdMap.getGroupName());
    }
    Assertions.assertEquals(0, identityAccessManager.getAllUsers().size());
    Assertions.assertEquals(0, identityAccessManager.getAllGroups().size());

    Faker faker = new Faker();
    Random random = new Random(System.currentTimeMillis());
    List<String> groupNames = new ArrayList<>();
    for (int x = 0; x < 10; x++) {
      Assertions.assertEquals(x, identityAccessManager.getAllGroups().size());
      String group = faker.starTrek().specie();
      while (identityAccessManager.getGroup(group) != null) {
        group = faker.starTrek().specie();
      }
      identityAccessManager.createGroup(group);
      groupNames.add(group);
    }

    Map<String, String> userPasswordMap = new LinkedHashMap<>();
    for (int x = 0; x < 100; x++) {
      Assertions.assertEquals(x, identityAccessManager.getAllUsers().size());
      String username = faker.starTrek().character();
      username = username.replaceAll(" ", "_");

      int count = 0;
      while (identityAccessManager.getUser(username) != null) {
        if (count > 90) {
          username = faker.witcher().character();
        } else if (count > 75) {
          username = faker.backToTheFuture().character();
        } else if (count > 60) {
          username = faker.zelda().character();
        } else if (count > 45) {
          username = faker.aquaTeenHungerForce().character();
        } else if (count > 30) {
          username = faker.lebowski().character();
        } else if (count > 15) {
          username = faker.lordOfTheRings().character();
        } else {
          username = faker.starTrek().character();
        }
        count++;
        username = username.replaceAll(" ", "_");
      }
      String password = PasswordGenerator.generateSalt(10 + Math.abs(random.nextInt(20)));
      identityAccessManager.createUser(username, password);
      String group = groupNames.get(Math.abs(random.nextInt(groupNames.size())));
      identityAccessManager.addUserToGroup(username, group);
      userPasswordMap.put(username, password);
      Assertions.assertEquals(username, identityAccessManager.getUser(username).getUsername());
      Assertions.assertNotNull(identityAccessManager.getUser(username).getAuthId());
    }

    for (Map.Entry<String, String> user : userPasswordMap.entrySet()) {
      Assertions.assertTrue(validateLogin(auth, user.getKey(), user.getValue()));
      Assertions.assertFalse(validateLogin(auth, user.getKey(), user.getValue() + "_bad_password"));
    }

    if (!mechanism.isEmpty()) {
      for (Map.Entry<String, String> user : userPasswordMap.entrySet()) {
        SaslTester saslTester = new SaslTester();
        saslTester.testMechanism(
            identityAccessManager.getIdentityLookup(), mechanism, user.getKey(), user.getValue());
      }
    }

    for (UserIdMap userIdMap : identityAccessManager.getAllUsers()) {
      identityAccessManager.deleteUser(userIdMap.getUsername());
    }
    List<GroupIdMap> groupList = identityAccessManager.getAllGroups();
    for (GroupIdMap groupIdMap : groupList) {
      identityAccessManager.deleteGroup(groupIdMap.getGroupName());
    }
    Assertions.assertEquals(0, identityAccessManager.getAllUsers().size());
    Assertions.assertEquals(0, identityAccessManager.getAllGroups().size());
  }

  private boolean validateLogin(String auth, String username, String password) {
    Map<String, String> initMap = new LinkedHashMap<>();
    initMap.put("siteWide", auth);
    Subject subject = new Subject();
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(username, password, "");

    IdentityLoginModule identityLoginModule = new IdentityLoginModule();
    identityLoginModule.initialize(subject, clientCallbackHandler, new LinkedHashMap<>(), initMap);
    boolean isValid = false;
    try {
      isValid = identityLoginModule.login();
      identityLoginModule.commit();
    } catch (LoginException e) {
    }

    return isValid;
  }
}
