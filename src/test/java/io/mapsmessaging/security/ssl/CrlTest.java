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

import io.mapsmessaging.security.certificates.CertificateUtils;
import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CrlTest {

  @Test
  void simpleCrlTest() throws IOException, CertificateException, OperatorCreationException {
    CertificateRevocationManager certificateRevocationManager = new CertificateRevocationManager(new URL("http://crls.pki.goog/gts1c3/zdATt0Ex_Fk.crl"), 10L*24L*60L*60L*1000L);
    Assertions.assertNotNull(certificateRevocationManager);
    Certificate cert = CertificateUtils.generateSelfSignedCertificateSecret("fred").getCertificate();
    Assertions.assertFalse(certificateRevocationManager.isCertificateRevoked((X509Certificate)cert));
  }
}
