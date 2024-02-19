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

package io.mapsmessaging.security.ssl;

import static io.mapsmessaging.security.logging.AuthLogMessages.*;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.CertificateManagerFactory;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.*;

public class SslHelper {

  private SslHelper() {
  }

  public static SSLContext createContext(String context, ConfigurationProperties config, Logger logger) throws IOException {
    SSLContext sslContext;
    // We have a physical socket bound, so now build up the SSL Context for this interface
    //
    ConfigurationProperties keyStoreProps = (ConfigurationProperties) config.get("keyStore");
    ConfigurationProperties trustStoreProps = (ConfigurationProperties) config.get("trustStore");

    String alias = keyStoreProps.getProperty("alias");
    try {
      // <editor-fold desc="Load and initialize the Key Store">
      //
      // Physically load the key stores from file
      //
      KeyStore keyStore = loadKeyStore(keyStoreProps);
      //
      // Initialise the Key Manager Factory, so we can use it in the SSL Engine
      //
      String sslKeyManagerFactory = keyStoreProps.getProperty("managerFactory");
      KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(sslKeyManagerFactory);
      keyManagerFactory.init(keyStore, keyStoreProps.getProperty("passphrase").toCharArray());
      logger.log(SSL_SERVER_INITIALISE, sslKeyManagerFactory);
      KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
      if (alias != null && !alias.isEmpty()) {
        for (int i = 0; i < keyManagers.length; i++) {
          if (keyManagers[i] instanceof X509ExtendedKeyManager) {
            keyManagers[i] = new CustomKeyManager((X509ExtendedKeyManager) keyManagers[i], alias);
          }
        }
      }

      // </editor-fold>

      // <editor-fold desc="Load and initialise the Trust Store">
      //
      // Load and initialise the trust store
      //
      KeyStore trustStore = loadKeyStore(trustStoreProps);

      //
      // Initialise the Trust Manager Factory from the trust store so we can validate it in the SSL
      // Context
      //
      String trustStoreManagerFactory = trustStoreProps.getProperty("managerFactory");
      TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustStoreManagerFactory);
      trustManagerFactory.init(trustStore);
      logger.log(SSL_SERVER_TRUST_MANAGER, trustStoreManagerFactory);
      // </editor-fold>

      // <editor-fold desc="Create the SSL Context">
      //
      // Put it all together and create the SSL Context to generate SSL Engines
      logger.log(SSL_SERVER_CONTEXT_CONSTRUCT);
      sslContext = SSLContext.getInstance(context);

      // Now check to see if there is a CRL configured, if so then construct the cert revocation during cert validation
      TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
      if(config.containsKey("crlUrl")){
        String crlUrlPath = config.getProperty("crlUrl");
        List<TrustManager> trustManagerList = Arrays.asList(trustManagers);
        CertificateRevocationManager certificateRevocationManager = new CertificateRevocationManager(new URL(crlUrlPath), config.getLongProperty("crlInterval", 60*60*24)); // Default daily
        trustManagerList.add(new CrlTrustManager(certificateRevocationManager));
        trustManagers = trustManagerList.toArray(trustManagers);
      }

      sslContext.init(keyManagers, trustManagers, new SecureRandom());
      logger.log(SSL_SERVER_SSL_CONTEXT_COMPLETE);
      // </editor-fold>

    } catch (KeyStoreException
             | IOException
             | NoSuchAlgorithmException
             | CertificateException
             | UnrecoverableKeyException
             | KeyManagementException e) {
      throw new IOException(e);
    }
    return sslContext;
  }

  public static SSLEngine createSSLEngine(SSLContext sslContext, ConfigurationProperties tls){
    SSLEngine sslEngine = sslContext.createSSLEngine();
    sslEngine.setNeedClientAuth(tls.getBooleanProperty("clientCertificateRequired", false));
    sslEngine.setWantClientAuth(tls.getBooleanProperty("clientCertificateWanted", false));
    return sslEngine;
  }

  private static KeyStore loadKeyStore(ConfigurationProperties properties)
      throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
    CertificateManager mananger = CertificateManagerFactory.getInstance().getManager(properties.getMap());
    return mananger.getKeyStore();
  }

}

