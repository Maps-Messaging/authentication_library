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
import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.CertificateManagerFactory;
import io.mapsmessaging.security.certificates.CertificateUtils;
import io.mapsmessaging.security.certificates.Ed25519IdentityManager;
import io.mapsmessaging.security.certificates.TrustedPeerKeyResolver;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

/** Administrator provisioning is separate from the runtime signing and verification methods. */
public final class TransportIdentityExample {

  private TransportIdentityExample() {
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 4 || !("provision".equals(args[0]) || "import-peer".equals(args[0]))) {
      throw new IllegalArgumentException(
          "Usage: TransportIdentityExample <provision|import-peer> <store.p12> <alias> <public.cer>");
    }
    CertificateManager manager = openStore(args[1]);
    Ed25519IdentityManager identities = new Ed25519IdentityManager(manager);
    if ("provision".equals(args[0])) {
      char[] entryPassword = requiredEnvironment("IDENTITY_KEY_PASSWORD").toCharArray();
      try {
        identities.createIdentity(args[2], entryPassword,
            new X500Principal("CN=transport-identity"), Duration.ofDays(365));
        Files.write(Path.of(args[3]), identities.exportCertificate(args[2]),
            StandardOpenOption.CREATE_NEW);
      } finally {
        Arrays.fill(entryPassword, '\0');
      }
    } else {
      // Explicit administrator action, after independently authenticating the public key.
      identities.importTrustedCertificate(args[2], Files.readAllBytes(Path.of(args[3])));
    }
    PublicKey publicKey = manager.getCertificate(args[2]).getPublicKey();
    System.out.println(CertificateUtils.publicKeyFingerprint(publicKey));
  }

  public static CertificateManager openStore(String path) throws Exception {
    ConfigurationProperties configuration = new ConfigurationProperties(Map.of(
        "type", "PKCS12",
        "path", path,
        "store_passphrase", requiredEnvironment("IDENTITY_STORE_PASSWORD")));
    return CertificateManagerFactory.getInstance().getManager(configuration);
  }

  public static byte[] sign(CertificateManager localStore, String localAlias,
      char[] entryPassword, byte[] transcript) throws Exception {
    PrivateKey privateKey = localStore.getKey(localAlias, entryPassword);
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(privateKey);
    signer.update(transcript);
    return signer.sign();
  }

  public static TrustedPeerKeyResolver trustedPeers(CertificateManager peerStore) {
    // Administrator-owned logical-peer registry. Stored certificates alone grant no permission.
    return new TrustedPeerKeyResolver(peerStore, Map.of(
        "warehouse", List.of("warehouse-current")));
  }

  public static boolean verify(TrustedPeerKeyResolver trustedPeers, String logicalPeer,
      PublicKey presentedKey, byte[] transcript, byte[] signature) throws Exception {
    if (!trustedPeers.isTrusted(logicalPeer, presentedKey)) {
      return false;
    }
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(presentedKey);
    verifier.update(transcript);
    return verifier.verify(signature);
  }

  private static String requiredEnvironment(String name) {
    String value = System.getenv(name);
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException("Set environment variable " + name);
    }
    return value;
  }
}
