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

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.CertificateManagerFactory;
import io.mapsmessaging.security.certificates.CertificateWithPrivateKey;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.impl.apache.ApacheBasicAuth;
import io.mapsmessaging.security.identity.impl.apache.HtGroupFileManager;
import io.mapsmessaging.security.passwords.PasswordHandler;

import java.io.File;
import java.security.cert.Certificate;

import static io.mapsmessaging.security.certificates.CertificateUtils.generateSelfSignedCertificateSecret;
import static io.mapsmessaging.security.logging.AuthLogMessages.ENCRYPTED_LOAD_FAILURE;

public class EncryptedAuth extends ApacheBasicAuth {

  private final Logger logger = LoggerFactory.getLogger(EncryptedAuth.class);
  public EncryptedAuth() {
    super();
  }

  public EncryptedAuth(String passwordFile, String groupFile, String alias, CertificateManager certificateManager, String keyPassword) {
    super(
        new EncryptedPasswordFileManager(passwordFile, alias, certificateManager, keyPassword),
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
  public IdentityLookup create(ConfigurationProperties config) {
    IdentityLookup identityLookup = null;
    String filePath = null;
    String groupFile = null;
    if (config.containsKey("passwordFile")) {
      filePath = config.getProperty("passwordFile");
      groupFile = "";
      if (config.containsKey("groupFile")) {
        groupFile = config.getProperty("groupFile");
      }
    } else if (config.containsKey("configDirectory")) {
      String directory = config.getProperty("configDirectory");
      File file = new File(directory);
      if (file.isDirectory()) {
        filePath = file.getAbsolutePath() + File.separator + ".htpassword-enc";
        groupFile = file.getAbsolutePath() + File.separator + ".htgroups";
      }
    }
    if (filePath != null) {
      try {
        identityLookup = construct(filePath, groupFile, config);
      } catch (Exception e) {
        logger.log(ENCRYPTED_LOAD_FAILURE, e);
      }
    }
    else{
      logger.log(ENCRYPTED_LOAD_FAILURE);
    }
    return identityLookup;
  }

  private EncryptedAuth construct(String passwordPath, String groupPath, ConfigurationProperties topConfig)
      throws Exception {
    ConfigurationProperties config = (ConfigurationProperties) topConfig.get("certificateStore");
    String alias = "";
    if (config.containsKey("alias")) {
      alias = config.getProperty("alias");
    }
    CertificateManager certificateManager = CertificateManagerFactory.getInstance().getManager(config);
    String keyPassword = config.getProperty("privateKey.passphrase");
    String privateKeyName = config.getProperty("privateKey.name");
    char[] privateKey = keyPassword.toCharArray();
    if (!certificateManager.getExists()) {
      CertificateWithPrivateKey certAndKey = generateSelfSignedCertificateSecret(alias);
      certificateManager.addCertificate(alias, certAndKey.getCertificate());
      certificateManager.addPrivateKey(
          privateKeyName,
          privateKey,
          certAndKey.getPrivateKey(),
          new Certificate[] {certAndKey.getCertificate()});
    }
    return new EncryptedAuth(passwordPath, groupPath, alias, certificateManager, keyPassword);
  }

  public PasswordHandler getPasswordHandler() {
    return ((EncryptedPasswordFileManager) passwdFileManager).getCipher();
  }
}
