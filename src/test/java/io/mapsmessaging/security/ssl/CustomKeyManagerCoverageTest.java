/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.ssl;

import static org.junit.jupiter.api.Assertions.*;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;
import org.junit.jupiter.api.Test;

class CustomKeyManagerCoverageTest {

  @Test
  void forcesConfiguredAliasAndDelegatesKeyMaterial() throws Exception {
    PrivateKey privateKey = new StubPrivateKey();
    X509Certificate[] chain = new X509Certificate[0];
    X509ExtendedKeyManager delegate = new StubKeyManager(privateKey, chain);
    CustomKeyManager manager = new CustomKeyManager(delegate, "maps");

    assertArrayEquals(new String[0], manager.getClientAliases("RSA", new Principal[0]));
    assertEquals("maps", manager.chooseClientAlias(new String[]{"RSA"}, new Principal[0], new Socket()));
    assertArrayEquals(new String[]{"maps"}, manager.getServerAliases("RSA", new Principal[0]));
    assertEquals("maps", manager.chooseServerAlias("RSA", new Principal[0], new Socket()));

    SSLEngine engine = SSLContext.getDefault().createSSLEngine();
    assertEquals("maps", manager.chooseEngineClientAlias(new String[]{"RSA"}, new Principal[0], engine));
    assertEquals("maps", manager.chooseEngineServerAlias("RSA", new Principal[0], engine));

    assertSame(privateKey, manager.getPrivateKey("other"));
    assertSame(chain, manager.getCertificateChain("other"));
  }

  private static final class StubKeyManager extends X509ExtendedKeyManager {
    private final PrivateKey privateKey;
    private final X509Certificate[] chain;

    private StubKeyManager(PrivateKey privateKey, X509Certificate[] chain) {
      this.privateKey = privateKey;
      this.chain = chain;
    }

    @Override public String[] getClientAliases(String keyType, Principal[] issuers) { return null; }
    @Override public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) { return null; }
    @Override public String[] getServerAliases(String keyType, Principal[] issuers) { return null; }
    @Override public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) { return null; }
    @Override public X509Certificate[] getCertificateChain(String alias) { return chain; }
    @Override public PrivateKey getPrivateKey(String alias) { return privateKey; }
  }

  private static final class StubPrivateKey implements PrivateKey {
    @Override public String getAlgorithm() { return "RSA"; }
    @Override public String getFormat() { return "PKCS#8"; }
    @Override public byte[] getEncoded() { return new byte[0]; }
  }
}
