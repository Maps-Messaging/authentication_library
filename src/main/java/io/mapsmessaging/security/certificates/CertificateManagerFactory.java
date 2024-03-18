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

package io.mapsmessaging.security.certificates;


import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.certificates.jvm.JvmKeyStoreManager;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ServiceLoader;

@SuppressWarnings("java:S6548") // yes it is a singleton
public class CertificateManagerFactory {

  private static class Holder {
    static final CertificateManagerFactory INSTANCE = new CertificateManagerFactory();
  }

  public static CertificateManagerFactory getInstance() {
    return CertificateManagerFactory.Holder.INSTANCE;
  }


  private final ServiceLoader<CertificateManager> certificateManagers;
  private final JvmKeyStoreManager jvmKeyStore = new JvmKeyStoreManager();

  private CertificateManagerFactory() {
    certificateManagers = ServiceLoader.load(CertificateManager.class);
  }

  public CertificateManager getManager(ConfigurationProperties config) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    for (CertificateManager certificateManager : certificateManagers) {
      if (certificateManager.isValid(config)) {
        return certificateManager.create(config);
      }
    }
    if(jvmKeyStore.isValid(config)){
      return jvmKeyStore.create(config);
    }
    throw new IOException("No certificate managers found for the config supplied");
  }

}
