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

package io.mapsmessaging.security.identity.impl.encrypted;

import io.mapsmessaging.security.certificates.pkcs11.Pkcs11Manager;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.impl.apache.ApacheBasicAuth;
import io.mapsmessaging.security.identity.impl.apache.HtGroupFileManager;
import java.io.File;
import java.util.Map;

public class EncryptedAuth extends ApacheBasicAuth {

  public EncryptedAuth() {
    super();
  }

  public EncryptedAuth(
      String passwordFile, String groupFile, String alias, Pkcs11Manager pkcs11Manager) {
    super(
        new EncryptedPasswordFileManager(passwordFile, alias, pkcs11Manager),
        new HtGroupFileManager(groupFile));
  }

  @Override
  public String getName() {
    return "Encrypted-Auth";
  }

  @Override
  public String getDomain() {
    return "encrypted";
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    String filePath = null;
    String groupFile = null;
    if (config.containsKey("passwordFile")) {
      filePath = config.get("passwordFile").toString();
      groupFile = "";
      if (config.containsKey("groupFile")) {
        groupFile = config.get("groupFile").toString();
      }
    } else if (config.containsKey("configDirectory")) {
      String directory = config.get("configDirectory").toString();
      File file = new File(directory);
      if (file.isDirectory()) {
        filePath = file.getAbsolutePath() + File.separator + ".htpassword-enc";
        groupFile = file.getAbsolutePath() + File.separator + ".htgroups";
      }
    }
    if (filePath != null) {
      return construct(filePath, groupFile, config);
    }
    return null;
  }

  private EncryptedAuth construct(String passwordPath, String groupPath, Map<String, ?> config) {
    String pkcs11ConfigPath = config.get("pkcs11ConfigPath").toString();
    String providerName = "SunPKCS11";
    String alias = "";
    if (config.containsKey("alias")) {
      alias = config.get("alias").toString();
    }
    if (config.containsKey("provider")) {
      providerName = config.get("provider").toString();
    }
    Pkcs11Manager pkcs11Manager = new Pkcs11Manager(pkcs11ConfigPath, providerName);

    return new EncryptedAuth(passwordPath, groupPath, alias, pkcs11Manager);
  }
}
