/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
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

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class CrlTrustManager extends X509ExtendedTrustManager {

  private final X509TrustManager trustManager;
  private final CertificateRevocationManager revocationManager;

  public CrlTrustManager(X509TrustManager trustManager, CertificateRevocationManager revocationManager) {
    this.trustManager = Objects.requireNonNull(trustManager);
    this.revocationManager = Objects.requireNonNull(revocationManager);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
    if (trustManager instanceof X509ExtendedTrustManager extendedTrustManager) {
      extendedTrustManager.checkClientTrusted(chain, authType, socket);
    } else {
      trustManager.checkClientTrusted(chain, authType);
    }
    checkRevocation(chain);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
    if (trustManager instanceof X509ExtendedTrustManager extendedTrustManager) {
      extendedTrustManager.checkServerTrusted(chain, authType, socket);
    } else {
      trustManager.checkServerTrusted(chain, authType);
    }
    checkRevocation(chain);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
    if (trustManager instanceof X509ExtendedTrustManager extendedTrustManager) {
      extendedTrustManager.checkClientTrusted(chain, authType, engine);
    } else {
      trustManager.checkClientTrusted(chain, authType);
    }
    checkRevocation(chain);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
    if (trustManager instanceof X509ExtendedTrustManager extendedTrustManager) {
      extendedTrustManager.checkServerTrusted(chain, authType, engine);
    } else {
      trustManager.checkServerTrusted(chain, authType);
    }
    checkRevocation(chain);
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    trustManager.checkClientTrusted(chain, authType);
    checkRevocation(chain);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    trustManager.checkServerTrusted(chain, authType);
    checkRevocation(chain);
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return trustManager.getAcceptedIssuers();
  }

  private void checkRevocation(X509Certificate[] chain) throws CertificateException {
    for (X509Certificate certificate : chain) {
      if (revocationManager.isCertificateRevoked(certificate)) {
        throw new CertificateException("Certificate is revoked");
      }
    }
  }
}
