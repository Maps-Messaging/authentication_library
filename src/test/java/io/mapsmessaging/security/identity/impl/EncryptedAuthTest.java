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
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.identity.impl.encrypted.EncryptedAuth;
import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EncryptedAuthTest  {

  private void deleteFiles(String[] files){
    for(String filename:files){
      File file = new File(filename);
      file.delete();
    }
  }

  @Test
  void testBasicFunctions() throws Exception {
    deleteFiles(new String[]{"./encKeyStore.jks","./.htpassword-enc", "./.htgroups" });
    String storePassword = PasswordGenerator.generateSalt(20);
    Map<String, Object> baseMap = new LinkedHashMap<>();
    Map<String, String> certificateMap = new LinkedHashMap<>();
    certificateMap.put("alias", "test");
    certificateMap.put("privateKey.passphrase", storePassword);
    certificateMap.put("privateKey.name", "test");
    certificateMap.put("type", "jks");
    certificateMap.put("path", "./encKeyStore.jks");
    certificateMap.put("passphrase", storePassword);


    baseMap.put("certificateStore", certificateMap);
    baseMap.put("passwordFile", "./.htpassword-enc" );
    baseMap.put("groupFile", "./.htgroups" );

    EncryptedAuth auth = (EncryptedAuth) IdentityLookupFactory.getInstance().get("Encrypted-Auth", baseMap);

    Faker faker = new Faker();
    Map<String, char[]> users = new LinkedHashMap<>();
    for (int x = 0; x < 100; x++) {
      String username = faker.name().username();
      char[] password = PasswordGenerator.generateSalt(20).toCharArray();
      users.put(username, password);
      auth.createUser(username, password, auth.getPasswordHandler());
    }

    for (String user : users.keySet()) {
      IdentityEntry entry = auth.findEntry(user);
      char[] pass = entry.getPassword();
      Assertions.assertArrayEquals(pass, users.get(user));
    }
  }

  @Test
  void testBasicDirectoryLoadFunctions() throws Exception {
    deleteFiles(new String[]{"./encKeyStore.jks","./.htpassword-enc", "./.htgroups" });
    String storePassword = PasswordGenerator.generateSalt(20);
    Map<String, Object> baseMap = new LinkedHashMap<>();
    Map<String, String> certificateMap = new LinkedHashMap<>();
    certificateMap.put("alias", "test");
    certificateMap.put("privateKey.passphrase", storePassword);
    certificateMap.put("privateKey.name", "test");
    certificateMap.put("type", "jks");
    certificateMap.put("path", "./encKeyStore.jks");
    certificateMap.put("passphrase", storePassword);


    baseMap.put("certificateStore", certificateMap);
    baseMap.put("configDirectory", "." );

    EncryptedAuth auth = (EncryptedAuth) IdentityLookupFactory.getInstance().get("Encrypted-Auth", baseMap);

    Faker faker = new Faker();
    Map<String, char[]> users = new LinkedHashMap<>();
    for (int x = 0; x < 100; x++) {
      String username = faker.name().username();
      char[] password = PasswordGenerator.generateSalt(20).toCharArray();
      users.put(username, password);
      auth.createUser(username, password, auth.getPasswordHandler());
    }

    for (String user : users.keySet()) {
      IdentityEntry entry = auth.findEntry(user);
      char[] pass = entry.getPassword();
      Assertions.assertArrayEquals(pass, users.get(user));
    }

    EncryptedAuth auth2 = (EncryptedAuth) IdentityLookupFactory.getInstance().get("Encrypted-Auth", baseMap);
    Assertions.assertEquals(auth.getEntries().size(), auth2.getEntries().size());
    for(IdentityEntry entry: auth.getEntries()){
      Assertions.assertEquals(entry.getUsername(), auth2.findEntry(entry.getUsername()).getUsername());
    }

  }
}
