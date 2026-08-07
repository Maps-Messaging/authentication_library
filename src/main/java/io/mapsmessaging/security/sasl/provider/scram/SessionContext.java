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

package io.mapsmessaging.security.sasl.provider.scram;

import io.mapsmessaging.security.passwords.PasswordHandler;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@SuppressWarnings("javaarchitecture:S7027")
public class SessionContext {

  private boolean receivedClientMessage;
  private boolean authenticationIdentityValid = true;
  private String clientNonce;
  private String serverNonce;
  private byte[] passwordSalt;
  private String username;
  private String authorizationId;
  private String authorizedId;
  private String gs2Header;
  private State state;
  private int iterations;
  private char[] prepPassword;
  private Mac mac;
  private String algorithm;
  private int keySize;
  private PasswordHandler passwordHasher;
  private String initialClientChallenge;
  private String initialServerChallenge;
  private String clientFinalWithoutProof;
  private byte[] clientKey;
  private byte[] storedKey;
  private byte[] clientSignature;
  private byte[] clientProof;
  private byte[] serverSignature;

  public void reset() {
    clear(prepPassword);
    clear(passwordSalt);
    clear(clientKey);
    clear(storedKey);
    clear(clientSignature);
    clear(clientProof);
    clear(serverSignature);
    if (mac != null) {
      mac.reset();
    }

    receivedClientMessage = false;
    authenticationIdentityValid = false;
    clientNonce = null;
    serverNonce = null;
    passwordSalt = null;
    username = null;
    authorizationId = null;
    authorizedId = null;
    gs2Header = null;
    state = null;
    iterations = 0;
    prepPassword = null;
    mac = null;
    algorithm = null;
    keySize = 0;
    passwordHasher = null;
    initialClientChallenge = null;
    initialServerChallenge = null;
    clientFinalWithoutProof = null;
    clientKey = null;
    storedKey = null;
    clientSignature = null;
    clientProof = null;
    serverSignature = null;
  }

  public void setServerNonce(String nonce) throws SaslException {
    ScramString.requireNonce(nonce);
    if (clientNonce == null || !nonce.startsWith(clientNonce) || nonce.length() == clientNonce.length()) {
      throw new SaslException("Server nonce must extend the client nonce");
    }
    serverNonce = nonce;
  }

  public void setMac(Mac mac) {
    if (mac == null || !"HmacSHA256".equalsIgnoreCase(mac.getAlgorithm())) {
      throw new IllegalArgumentException("Only HmacSHA256 is supported");
    }
    this.mac = mac;
    algorithm = "SHA-256";
    keySize = 256;
  }

  public byte[] generateSaltedPassword(char[] password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, keySize);
    try {
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    } finally {
      spec.clearPassword();
    }
  }

  public byte[] generateSaltedPassword(byte[] password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException, InvalidKeySpecException {
    char[] characters = new String(password, StandardCharsets.UTF_8).toCharArray();
    try {
      return generateSaltedPassword(characters, salt, iterationCount);
    } finally {
      clear(characters);
    }
  }

  public byte[] computeHmac(byte[] key, String value) throws InvalidKeyException {
    mac.reset();
    mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
    return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
  }

  public void computeServerSignature(char[] password, String authString) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] saltedPassword = generateSaltedPassword(password, passwordSalt, iterations);
    try {
      byte[] serverKey = computeHmac(saltedPassword, "Server Key");
      try {
        serverSignature = computeHmac(serverKey, authString);
      } finally {
        clear(serverKey);
      }
    } finally {
      clear(saltedPassword);
    }
  }

  public void computeServerSignature(byte[] password, String authString) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    char[] characters = new String(password, StandardCharsets.UTF_8).toCharArray();
    try {
      computeServerSignature(characters, authString);
    } finally {
      clear(characters);
    }
  }

  public void computeClientKey(char[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] saltedPassword = generateSaltedPassword(password, passwordSalt, iterations);
    try {
      clientKey = computeHmac(saltedPassword, "Client Key");
    } finally {
      clear(saltedPassword);
    }
  }

  public void computeClientKey(byte[] password) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    char[] characters = new String(password, StandardCharsets.UTF_8).toCharArray();
    try {
      computeClientKey(characters);
    } finally {
      clear(characters);
    }
  }

  public void computeStoredKeyAndSignature(String authString) throws NoSuchAlgorithmException, InvalidKeyException {
    storedKey = MessageDigest.getInstance(algorithm).digest(clientKey);
    clientSignature = computeHmac(storedKey, authString);
  }

  public void computeClientHashes(char[] password, String authString) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    computeClientKey(password);
    computeStoredKeyAndSignature(authString);
    clientProof = clientKey.clone();
    for (int i = 0; i < clientProof.length; i++) {
      clientProof[i] ^= clientSignature[i];
    }
  }

  public void computeClientHashes(byte[] password, String authString) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    char[] characters = new String(password, StandardCharsets.UTF_8).toCharArray();
    try {
      computeClientHashes(characters, authString);
    } finally {
      clear(characters);
    }
  }

  private static void clear(byte[] value) {
    if (value != null) {
      Arrays.fill(value, (byte) 0);
    }
  }

  private static void clear(char[] value) {
    if (value != null) {
      Arrays.fill(value, '\0');
    }
  }
}
