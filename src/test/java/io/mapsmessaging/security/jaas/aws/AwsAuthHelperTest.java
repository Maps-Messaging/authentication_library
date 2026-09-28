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
 */

package io.mapsmessaging.security.jaas.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AwsAuthHelperTest {

  private static final String KEY_ID = "cognito-access-key";
  private static final String ISSUER = "https://cognito-idp.ap-southeast-2.amazonaws.com/pool-id";
  private static final String CLIENT_ID = "broker-client";
  private static RSAKeyProvider keyProvider;
  private static Algorithm signingAlgorithm;

  @BeforeAll
  static void createSigningKey() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    keyProvider = new TestKeyProvider(publicKey, privateKey);
    signingAlgorithm = Algorithm.RSA256(keyProvider);
  }

  @Test
  void validatesAccessTokenForConfiguredClient() {
    DecodedJWT jwt = AwsAuthHelper.validateAccessToken(createToken("access", CLIENT_ID), ISSUER, CLIENT_ID, keyProvider);

    assertEquals("cognito-user-subject", jwt.getSubject());
    assertEquals(List.of("operators"), AwsAuthHelper.getGroups(jwt));
  }

  @Test
  void rejectsAccessTokenForAnotherClient() {
    String token = createToken("access", "another-client");

    assertThrows(JWTVerificationException.class, () -> AwsAuthHelper.validateAccessToken(token, ISSUER, CLIENT_ID, keyProvider));
  }

  @Test
  void rejectsIdTokenOnAccessTokenPath() {
    String token = createToken("id", CLIENT_ID);

    assertThrows(JWTVerificationException.class, () -> AwsAuthHelper.validateAccessToken(token, ISSUER, CLIENT_ID, keyProvider));
  }

  private static String createToken(String tokenUse, String clientId) {
    return JWT.create()
        .withKeyId(KEY_ID)
        .withIssuer(ISSUER)
        .withSubject("cognito-user-subject")
        .withClaim("token_use", tokenUse)
        .withClaim("client_id", clientId)
        .withArrayClaim("cognito:groups", new String[] {"operators"})
        .withIssuedAt(Date.from(Instant.now().minusSeconds(1)))
        .withExpiresAt(Date.from(Instant.now().plusSeconds(300)))
        .sign(signingAlgorithm);
  }

  private record TestKeyProvider(RSAPublicKey publicKey, RSAPrivateKey privateKey) implements RSAKeyProvider {

    @Override
    public RSAPublicKey getPublicKeyById(String kid) {
      return KEY_ID.equals(kid) ? publicKey : null;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
      return privateKey;
    }

    @Override
    public String getPrivateKeyId() {
      return KEY_ID;
    }
  }
}
