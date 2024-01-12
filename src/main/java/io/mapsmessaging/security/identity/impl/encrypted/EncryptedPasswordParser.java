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

import io.mapsmessaging.security.certificates.BufferCipher;
import io.mapsmessaging.security.certificates.pkcs11.Pkcs11Manager;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.Getter;
import lombok.Setter;

public class EncryptedPasswordParser implements PasswordParser {

  private byte[] password;
  private String alias;

  @Getter @Setter private Pkcs11Manager pkcs11Manager;

  public EncryptedPasswordParser(Pkcs11Manager pkcs11Manager) {
    this.pkcs11Manager = pkcs11Manager;
  }

  public EncryptedPasswordParser(Pkcs11Manager pkcs11Manager, String alias, byte[] password) {
    this.pkcs11Manager = pkcs11Manager;
    this.alias = alias;
    this.password = password;
  }

  @Override
  public PasswordParser create(String password) {
    String t = password.substring(getKey().length());
    int dollar = t.indexOf("$");
    String al = t.substring(0, dollar);
    byte[] pass = t.substring(dollar + 1).getBytes(StandardCharsets.UTF_8);
    return new EncryptedPasswordParser(pkcs11Manager, al, pass);
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
  public byte[] transformPassword(byte[] password, byte[] salt, int cost) {
    BufferCipher bufferCipher = new BufferCipher(pkcs11Manager);
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
    return (getKey() + alias + "$" + encoded).getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public byte[] getPassword() {
    BufferCipher bufferCipher = new BufferCipher(pkcs11Manager);
    byte[] decoded = Base64.getDecoder().decode(password);
    byte[] decrypted = bufferCipher.decrypt(alias, decoded, null);

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
    return originalPassword;
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getKey() + alias + "$" + new String(password)).toCharArray();
  }

  @Override
  public String getName() {
    return "RSA Encrypted Password";
  }
}
