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

import java.io.InputStream;
import java.net.URL;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

public class CertificateRevocationManager {

  private final URL crlUrl;
  private final long timeInterval;
  private long lastLoad;
  private final AtomicReference<CRL> crl;


  public CertificateRevocationManager(URL url, long interval){
    crlUrl = url;
    timeInterval = interval;
    lastLoad = 0;
    crl = new AtomicReference<>();
  }

 private void loadCrl() {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      try (InputStream crlStream = crlUrl.openStream()) {
        CRL crlLoad = cf.generateCRL(crlStream);
        crl.compareAndExchange(crl.get(), crlLoad);
      }
      lastLoad = System.currentTimeMillis()+timeInterval;
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public boolean isCertificateRevoked(X509Certificate certificate){
    if(lastLoad < System.currentTimeMillis()){
      loadCrl();
    }
    return crl.get().isRevoked(certificate);
  }

}
