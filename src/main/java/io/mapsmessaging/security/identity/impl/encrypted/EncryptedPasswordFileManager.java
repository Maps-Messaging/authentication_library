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

package io.mapsmessaging.security.identity.impl.encrypted;

import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.impl.apache.HtPasswdFileManager;

public class EncryptedPasswordFileManager extends HtPasswdFileManager {

  private final EncryptedPasswordParser parser;

  public EncryptedPasswordFileManager(String filepath, String certAlias, CertificateManager pkcs11Manager, String privateKeyPassword) {
    super(filepath);
    this.parser = new EncryptedPasswordParser(pkcs11Manager, certAlias, privateKeyPassword);
  }

  @Override
  protected IdentityEntry create(String username, String hash) {
    return new EncryptedPasswordEntry(username, hash, parser);
  }

  @Override
  protected IdentityEntry load(String line) {
    return new EncryptedPasswordEntry(line, parser);
  }
}
