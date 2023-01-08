/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

package io.mapsmessaging.security.sasl.provider.scram.util;

import io.mapsmessaging.security.crypto.CryptoHelper;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.sasl.provider.scram.State;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;
import lombok.Getter;
import lombok.Setter;

public class SessionContext {

  @Getter
  @Setter
  private boolean receivedClientMessage = false;

  @Getter
  @Setter
  private String clientNonce;

  @Getter
  private String serverNonce;

  @Getter
  @Setter
  private String passwordSalt;

  @Getter
  @Setter
  private String username;

  @Getter
  @Setter
  private State state;

  @Getter
  @Setter
  private int interations;

  @Getter
  @Setter
  private String prepPassword;

  @Getter
  private Mac mac;

  private String algorithm;

  @Getter
  @Setter
  private PasswordParser passwordParser;

  @Getter
  @Setter
  private String initialClientChallenge;

  @Getter
  @Setter
  private String initialServerChallenge;

  @Getter
  private byte[] clientKey;

  @Getter
  private byte[] storedKey;

  @Getter
  private byte[] clientSignature;

  @Getter
  private byte[] clientProof;

  @Getter
  private byte[] serverSignature;

  public void setServerNonce(String nonce) throws SaslException {
    if (!nonce.startsWith(clientNonce)) {
      throw new SaslException("Server Nonce must start with client nonce");
    }
    serverNonce = nonce;
  }

  public void setMac(Mac mac) {
    this.mac = mac;
    algorithm = mac.getAlgorithm().substring("hmac".length());
    if (algorithm.toLowerCase().startsWith("sha") && !algorithm.toLowerCase().startsWith("sha-")) {
      algorithm = algorithm.substring(0, "sha".length()) + "-" + algorithm.substring("sha".length());
    }
  }

  public byte[] computeHmac(byte[] key, String string) throws InvalidKeyException {
    mac.reset();
    SecretKeySpec secretKey = new SecretKeySpec(key, mac.getAlgorithm());
    mac.init(secretKey);
    mac.update(string.getBytes());
    return mac.doFinal();
  }

  public void computeServerSignature(byte[] password, String authString) throws InvalidKeyException, NoSuchAlgorithmException {
    byte[] serverKey = computeHmac(password, "Server Key");
    MessageDigest messageDigest = CryptoHelper.findDigest(algorithm);
    byte[] tmp = messageDigest.digest(serverKey);
    serverSignature = computeHmac(tmp, authString);
  }

  public void computeClientKey(byte[] password) throws InvalidKeyException {
    clientKey = computeHmac(password, "Client Key");
  }

  public void computeStoredKeyAndSignature(String authString) throws NoSuchAlgorithmException, InvalidKeyException {
    MessageDigest messageDigest = CryptoHelper.findDigest(algorithm);
    storedKey = messageDigest.digest(clientKey);
    clientSignature = computeHmac(storedKey, authString);
  }

  public void computeClientHashes(byte[] password, String authString) throws InvalidKeyException, NoSuchAlgorithmException {
    computeClientKey(password);
    computeStoredKeyAndSignature(authString);
    clientProof = clientKey.clone();
    for (int i = 0; i < clientProof.length; i++) {
      clientProof[i] ^= clientSignature[i];
    }
  }
}
