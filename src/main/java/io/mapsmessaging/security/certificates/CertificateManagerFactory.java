/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.certificates;


import lombok.Getter;

import java.io.IOException;
import java.util.Map;
import java.util.ServiceLoader;

public class CertificateManagerFactory {

  static {
    instance = new CertificateManagerFactory();
  }

  @Getter
  private static final CertificateManagerFactory instance;

  private final ServiceLoader<CertificateManager> certificateManagers;

  private CertificateManagerFactory() {
    certificateManagers = ServiceLoader.load(CertificateManager.class);
  }

  public CertificateManager getManager(Map<String, ?> config) throws Exception {
    for (CertificateManager certificateManager : certificateManagers) {
      if (certificateManager.isValid(config)) {
        return certificateManager.create(config);
      }
    }
    throw new IOException("No certificate manangers found for the config supplied");
  }

}
