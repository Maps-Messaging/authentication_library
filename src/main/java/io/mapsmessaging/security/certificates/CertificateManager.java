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

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public interface CertificateManager {
  Certificate getCertificate(String alias) throws CertificateException;

  void addCertificate(String alias, Certificate certificate) throws CertificateException;

  void deleteCertificate(String alias) throws CertificateException;

  PrivateKey getKey(String alias, char[] keyPassword) throws CertificateException;

  void addPrivateKey(String alias, char[] password, PrivateKey privateKey, Certificate[] certChain)
      throws CertificateException;
}
