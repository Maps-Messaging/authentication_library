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

package io.mapsmessaging.security.passwords.ciphers;

import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.cipher.BufferCipher;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordCipher;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.util.ArrayHelper;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import lombok.Getter;
import lombok.Setter;

public class EncryptedPasswordCipher implements PasswordCipher {

  private PasswordBuffer password;

  private String privateKeyPassword;

  @Getter
  private final String alias;

  @Getter
  @Setter
  private CertificateManager certificateManager;

  public EncryptedPasswordCipher() {
    alias = "";

  }

  public EncryptedPasswordCipher(
      CertificateManager certificateManager, String alias, String privateKeyPassword) {
    this.certificateManager = certificateManager;
    this.alias = alias;
    this.privateKeyPassword = privateKeyPassword;
  }

  public EncryptedPasswordCipher(
      CertificateManager certificateManager,
      String alias,
      char[] password,
      String privateKeyPassword) {
    this.certificateManager = certificateManager;
    this.alias = alias;
    this.password = new PasswordBuffer(password);
    this.privateKeyPassword = privateKeyPassword;
  }


  @Override
  public PasswordHandler create(char[] password) {
    String sub = new String(password);
    String t = sub.substring(getKey().length());
    int dollar = t.indexOf("$");
    String al = t.substring(0, dollar);
    char[] pass = t.substring(dollar + 1).toCharArray();
    return new EncryptedPasswordCipher(certificateManager, al, pass, privateKeyPassword);
  }

  @Override
  public String getKey() {
    return "{encrypted}";
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @Override
  public char[] transformPassword(char[] password, byte[] salt, int cost)
      throws GeneralSecurityException, IOException {
    BufferCipher bufferCipher = new BufferCipher(certificateManager);
    if (salt.length > 256) {
      byte[] t = new byte[255];
      System.arraycopy(salt, 0, t, 0, t.length);
      salt = t;
    }
    byte[] b = new byte[salt.length + password.length + 1];
    b[0] = (byte) salt.length;
    byte[] xorPassword = new byte[password.length];
    for (int i = 0; i < password.length; i++) {
      xorPassword[i] = (byte) (password[i] ^ salt[i % salt.length]);
    }
    System.arraycopy(salt, 0, b, 1, salt.length);
    System.arraycopy(xorPassword, 0, b, salt.length + 1, xorPassword.length);
    String encoded = Base64.getEncoder().encodeToString(bufferCipher.encrypt(alias, b));
    return ArrayHelper.appendCharArrays(getKey().toCharArray(), alias.toCharArray(), "$".toCharArray(), encoded.toCharArray());
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public char[] getPassword() throws GeneralSecurityException, IOException {
    BufferCipher bufferCipher = new BufferCipher(certificateManager);
    byte[] decoded = Base64.getDecoder().decode(password.getBytes());
    byte[] decrypted = bufferCipher.decrypt(alias, decoded, privateKeyPassword.toCharArray());

    int saltLength = decrypted[0];
    byte[] salt = new byte[saltLength];
    byte[] xorPassword = new byte[decrypted.length - saltLength - 1];

    System.arraycopy(decrypted, 1, salt, 0, saltLength);
    System.arraycopy(decrypted, saltLength + 1, xorPassword, 0, xorPassword.length);

    // Apply XOR with the salt to the password
    byte[] originalPassword = new byte[xorPassword.length];
    for (int i = 0; i < xorPassword.length; i++) {
      originalPassword[i] = (byte) (xorPassword[i] ^ salt[i % salt.length]);
    }
    return new String(originalPassword).toCharArray();
  }

  @Override
  public char[] getFullPasswordHash() {
    return ArrayHelper.appendCharArrays(getKey().toCharArray(), alias.toCharArray(), "$".toCharArray(), password.getHash());
  }

  @Override
  public String getName() {
    return "RSA Encrypted Password";
  }
}
