/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.ssl.SslHelper;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/** Loads pre-provisioned PKCS12 stores and performs a hostname-verified client handshake. */
public final class TlsExample {

  private TlsExample() {
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      throw new IllegalArgumentException(
          "Usage: TlsExample <identity.p12> <trust.p12> <identity-alias> <host> <port>");
    }
    SSLContext context = createContext(args[0], args[1], args[2]);
    try (SSLSocket socket = (SSLSocket) context.getSocketFactory()
        .createSocket(args[3], Integer.parseInt(args[4]))) {
      socket.setUseClientMode(true);
      SSLParameters parameters = socket.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      socket.setSSLParameters(parameters);
      socket.startHandshake();
      System.out.println("TLS handshake completed: " + socket.getSession().getProtocol());
    }
  }

  public static SSLContext createContext(String identityPath, String trustPath, String alias)
      throws Exception {
    ConfigurationProperties keyStore = new ConfigurationProperties(Map.of(
        "type", "PKCS12",
        "path", identityPath,
        "store_passphrase", requiredEnvironment("TLS_STORE_PASSWORD"),
        "passphrase", requiredEnvironment("TLS_KEY_PASSWORD"),
        "alias", alias,
        "managerFactory", KeyManagerFactory.getDefaultAlgorithm()));
    ConfigurationProperties trustStore = new ConfigurationProperties(Map.of(
        "type", "PKCS12",
        "path", trustPath,
        "store_passphrase", requiredEnvironment("TLS_TRUST_PASSWORD"),
        "passphrase", requiredEnvironment("TLS_TRUST_PASSWORD"),
        "managerFactory", TrustManagerFactory.getDefaultAlgorithm()));
    ConfigurationProperties configuration = new ConfigurationProperties();
    configuration.put("keyStore", keyStore);
    configuration.put("trustStore", trustStore);
    // Optional CRL configuration belongs here, outside the two store objects:
    // configuration.put("crlUrl", "https://pki.example/crl.der");
    // configuration.put("crlInterval", 3600000L); // milliseconds
    return SslHelper.createContext("TLSv1.3", configuration,
        LoggerFactory.getLogger(TlsExample.class));
  }

  /** The host transport must drive wrap/unwrap, delegated tasks, buffers and connection closure. */
  public static SSLEngine createMutualTlsServerEngine(SSLContext context) {
    ConfigurationProperties tls = new ConfigurationProperties(Map.of(
        "clientCertificateRequired", true,
        "clientCertificateWanted", false));
    SSLEngine engine = SslHelper.createSSLEngine(context, tls);
    engine.setUseClientMode(false);
    return engine;
  }

  private static String requiredEnvironment(String name) {
    String value = System.getenv(name);
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException("Set environment variable " + name);
    }
    return value;
  }
}
