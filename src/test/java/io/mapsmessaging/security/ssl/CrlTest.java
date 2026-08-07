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

package io.mapsmessaging.security.ssl;

import io.mapsmessaging.security.certificates.CertificateUtils;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class CrlTest {

  @Test
  void configured_crl_check_runs_after_default_trust_validation() throws Exception {
    X509Certificate certificate = createCertificate();
    AtomicBoolean trustValidationCalled = new AtomicBoolean();
    CrlTrustManager trustManager = new CrlTrustManager(
        new RecordingTrustManager(certificate, trustValidationCalled),
        revocationManager(false));

    trustManager.checkServerTrusted(new X509Certificate[]{certificate}, "RSA");

    Assertions.assertTrue(trustValidationCalled.get());
    Assertions.assertArrayEquals(new X509Certificate[]{certificate}, trustManager.getAcceptedIssuers());
  }

  @Test
  void revoked_certificate_is_rejected() throws Exception {
    X509Certificate certificate = createCertificate();
    CrlTrustManager trustManager = new CrlTrustManager(
        new RecordingTrustManager(certificate, new AtomicBoolean()),
        revocationManager(true));

    Assertions.assertThrows(
        CertificateException.class,
        () -> trustManager.checkServerTrusted(new X509Certificate[]{certificate}, "RSA"));
  }

  private X509Certificate createCertificate() throws CertificateException, OperatorCreationException {
    Certificate certificate = CertificateUtils.generateSelfSignedCertificateSecret("fred").getCertificate();
    return (X509Certificate) certificate;
  }

  private CertificateRevocationManager revocationManager(boolean revoked) throws Exception {
    return new CertificateRevocationManager(new URL("file:/unused.crl"), 1000L) {
      @Override
      public boolean isCertificateRevoked(X509Certificate certificate) {
        return revoked;
      }
    };
  }

  private static final class RecordingTrustManager implements X509TrustManager {

    private final X509Certificate[] acceptedIssuers;
    private final AtomicBoolean validationCalled;

    private RecordingTrustManager(X509Certificate acceptedIssuer, AtomicBoolean validationCalled) {
      this.acceptedIssuers = new X509Certificate[]{acceptedIssuer};
      this.validationCalled = validationCalled;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
      validationCalled.set(true);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
      validationCalled.set(true);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return acceptedIssuers;
    }
  }
}
