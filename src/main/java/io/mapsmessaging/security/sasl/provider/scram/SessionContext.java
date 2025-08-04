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

package io.mapsmessaging.security.sasl.provider.scram;

import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@SuppressWarnings("javaarchitecture:S7027") // yes SessionContext uses state
public class SessionContext {

  private static final String[] HMAC_NAMES = {"sha3", "sha"};

  private boolean receivedClientMessage = false;
  private String clientNonce;
  private String serverNonce;
  private byte[] passwordSalt;
  private String username;
  private State state;
  private int iterations;
  private char[] prepPassword;
  private Mac mac;
  private String algorithm;
  private int keySize;
  private PasswordHandler passwordHasher;
  private String initialClientChallenge;
  private String initialServerChallenge;
  private byte[] clientKey;
  private byte[] storedKey;
  private byte[] clientSignature;
  private byte[] clientProof;
  private byte[] serverSignature;

  public void reset() {
    mac.reset();

    state = null;
    mac = null;
    passwordHasher = null;

    username = "";
    passwordSalt = new byte[0];
    clientNonce = "";
    serverNonce = "";
    initialServerChallenge = "";
    algorithm = "";
    keySize = 0;
    prepPassword = new char[0];

    Arrays.fill(clientKey, (byte) 0);
    Arrays.fill(clientSignature, (byte) 0);
    Arrays.fill(storedKey, (byte) 0);
    Arrays.fill(serverSignature, (byte) 0);
  }

  public void setServerNonce(String nonce) throws SaslException {
    if (!nonce.startsWith(clientNonce)) {
      throw new SaslException("Server Nonce must start with client nonce");
    }
    serverNonce = nonce;
  }

  public void setMac(Mac mac) {
    this.mac = mac;
    algorithm = mac.getAlgorithm().substring("hmac".length());
    String name = algorithm.toLowerCase();
    name = name.replace("-", "");
    String keyLen = "";
    for (String test : HMAC_NAMES) {
      if (name.startsWith(test)) {
        keyLen = name.substring(test.length());
        break;
      }
    }
    keySize = Integer.parseInt(keyLen);
  }

  public byte[] generateSaltedPassword(byte[] password, byte[] salt, int iterations)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA" + keySize);
    PBEKeySpec spec = new PBEKeySpec(new String(password).toCharArray(), salt, iterations, keySize);
    SecretKey key = factory.generateSecret(spec);
    return key.getEncoded();
  }

  public byte[] computeHmac(byte[] key, String string) throws InvalidKeyException {
    mac.reset();
    SecretKeySpec secretKey = new SecretKeySpec(key, mac.getAlgorithm());
    mac.init(secretKey);
    mac.update(string.getBytes(StandardCharsets.UTF_8));
    return mac.doFinal();
  }

  public void computeServerSignature(byte[] password, String authString)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] saltedPassword =
        generateSaltedPassword(password, Base64.getDecoder().decode(passwordSalt), iterations);
    byte[] serverKey = computeHmac(saltedPassword, "Server Key");
    MessageDigest messageDigest = CryptoHelper.findDigest(algorithm);
    byte[] tmp = messageDigest.digest(serverKey);
    serverSignature = computeHmac(tmp, authString);
  }

  public void computeClientKey(byte[] password)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] saltedPassword =
        generateSaltedPassword(password, Base64.getDecoder().decode(passwordSalt), iterations);
    clientKey = computeHmac(saltedPassword, "Client Key");
  }

  public void computeStoredKeyAndSignature(String authString) throws NoSuchAlgorithmException, InvalidKeyException {
    MessageDigest messageDigest = CryptoHelper.findDigest(algorithm);
    storedKey = messageDigest.digest(clientKey);
    clientSignature = computeHmac(storedKey, authString);
  }

  public void computeClientHashes(byte[] password, String authString)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    computeClientKey(password);
    computeStoredKeyAndSignature(authString);
    clientProof = clientKey.clone();
    for (int i = 0; i < clientProof.length; i++) {
      clientProof[i] ^= clientSignature[i];
    }
  }
}
