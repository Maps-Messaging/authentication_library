/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.ssl;

import static org.junit.jupiter.api.Assertions.*;

import java.net.Socket;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.api.Test;

class CrlTrustManagerCoverageTest {

  @Test
  void delegatesAllTrustChecksAndAcceptsNonRevokedCertificates() throws Exception {
    StubTrustManager delegate = new StubTrustManager();
    StubRevocationManager revocation = new StubRevocationManager(false, false);
    CrlTrustManager manager = new CrlTrustManager(delegate, revocation);
    X509Certificate[] chain = new X509Certificate[]{null};
    Socket socket = new Socket();
    SSLEngine engine = SSLContext.getDefault().createSSLEngine();

    manager.checkClientTrusted(chain, "RSA");
    manager.checkServerTrusted(chain, "RSA");
    manager.checkClientTrusted(chain, "RSA", socket);
    manager.checkServerTrusted(chain, "RSA", socket);
    manager.checkClientTrusted(chain, "RSA", engine);
    manager.checkServerTrusted(chain, "RSA", engine);

    assertEquals(6, revocation.checks);
    assertSame(delegate.acceptedIssuers, manager.getAcceptedIssuers());
    assertEquals(1, delegate.clientBasic);
    assertEquals(1, delegate.serverBasic);
    assertEquals(1, delegate.clientSocket);
    assertEquals(1, delegate.serverSocket);
    assertEquals(1, delegate.clientEngine);
    assertEquals(1, delegate.serverEngine);
  }

  @Test
  void rejectsRevokedCertificateAndWrapsRevocationRuntimeFailure() throws Exception {
    X509Certificate[] chain = new X509Certificate[]{null};

    CrlTrustManager revoked =
        new CrlTrustManager(new StubTrustManager(), new StubRevocationManager(true, false));
    CertificateException revokedException =
        assertThrows(CertificateException.class, () -> revoked.checkServerTrusted(chain, "RSA"));
    assertEquals("Certificate is revoked", revokedException.getMessage());

    CrlTrustManager failed =
        new CrlTrustManager(new StubTrustManager(), new StubRevocationManager(false, true));
    CertificateException failure =
        assertThrows(CertificateException.class, () -> failed.checkClientTrusted(chain, "RSA"));
    assertEquals("Unable to validate certificate revocation status", failure.getMessage());
    assertInstanceOf(IllegalStateException.class, failure.getCause());
  }

  @Test
  void constructorRejectsNullCollaborators() throws Exception {
    StubRevocationManager revocation = new StubRevocationManager(false, false);
    assertThrows(NullPointerException.class, () -> new CrlTrustManager(null, revocation));
    assertThrows(NullPointerException.class, () -> new CrlTrustManager(new StubTrustManager(), null));
  }

  private static final class StubRevocationManager extends CertificateRevocationManager {
    private final boolean revoked;
    private final boolean fail;
    private int checks;

    private StubRevocationManager(boolean revoked, boolean fail) throws Exception {
      super(new URL("file:/tmp/no-crl-needed"), 1000);
      this.revoked = revoked;
      this.fail = fail;
    }

    @Override
    public boolean isCertificateRevoked(X509Certificate certificate) {
      checks++;
      if (fail) {
        throw new IllegalStateException("boom");
      }
      return revoked;
    }
  }

  private static final class StubTrustManager extends X509ExtendedTrustManager {
    private final X509Certificate[] acceptedIssuers = new X509Certificate[0];
    private int clientBasic;
    private int serverBasic;
    private int clientSocket;
    private int serverSocket;
    private int clientEngine;
    private int serverEngine;

    @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { clientBasic++; }
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { serverBasic++; }
    @Override public X509Certificate[] getAcceptedIssuers() { return acceptedIssuers; }
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) { clientSocket++; }
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) { serverSocket++; }
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { clientEngine++; }
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { serverEngine++; }
  }
}
