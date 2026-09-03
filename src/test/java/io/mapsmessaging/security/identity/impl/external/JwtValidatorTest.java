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

package io.mapsmessaging.security.identity.impl.external;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class JwtValidatorTest {

  private static final String KEY_ID = "tenant-key-1";
  private static final String ISSUER = "https://tenant.example/";
  private static final String AUDIENCE = "broker-client";
  private static final String SUBJECT = "auth0|mallory";

  private static Algorithm signingAlgorithm;
  private static Jwk jwk;

  @BeforeAll
  static void createSigningKey() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    signingAlgorithm = Algorithm.RSA256(publicKey, privateKey);

    Map<String, Object> values = new HashMap<>();
    values.put("kid", KEY_ID);
    values.put("kty", "RSA");
    values.put("alg", "RS256");
    values.put("use", "sig");
    values.put("n", encode(publicKey.getModulus()));
    values.put("e", encode(publicKey.getPublicExponent()));
    jwk = Jwk.fromValues(values);
  }

  @Test
  void acceptsIdTokenForExpectedSubjectAndApplication() throws Exception {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(false));

    DecodedJWT jwt = validator.validateJwt(SUBJECT, createToken(ISSUER, SUBJECT, AUDIENCE, null, Instant.now().plusSeconds(300)));

    assertEquals(SUBJECT, jwt.getSubject());
  }

  @Test
  void rejectsAttackersTokenForVictimSubject() {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(false));
    String token = createToken(ISSUER, SUBJECT, AUDIENCE, null, Instant.now().plusSeconds(300));

    assertThrows(JWTVerificationException.class, () -> validator.validateJwt("auth0|admin", token));
  }

  @Test
  void rejectsTokenIssuedForAnotherApplication() {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(false));
    String token = createToken(ISSUER, SUBJECT, "unrelated-api", null, Instant.now().plusSeconds(300));

    assertThrows(JWTVerificationException.class, () -> validator.validateJwt(SUBJECT, token));
  }

  @Test
  void rejectsTokenFromUnexpectedIssuer() {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(false));
    String token = createToken("https://other-tenant.example/", SUBJECT, AUDIENCE, null, Instant.now().plusSeconds(300));

    assertThrows(JWTVerificationException.class, () -> validator.validateJwt(SUBJECT, token));
  }

  @Test
  void rejectsExpiredToken() {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(false));
    String token = createToken(ISSUER, SUBJECT, AUDIENCE, null, Instant.now().minusSeconds(1));

    assertThrows(JWTVerificationException.class, () -> validator.validateJwt(SUBJECT, token));
  }

  @Test
  void rejectsCognitoAccessTokenEvenForExpectedApplication() throws Exception {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(true));
    String token = createToken(ISSUER, SUBJECT, AUDIENCE, "access", Instant.now().plusSeconds(300));

    assertNull(validator.validateJwt(SUBJECT, token));
  }

  @Test
  void rejectsTokenWhenTrustedSubjectIsUnavailable() throws Exception {
    JwtValidator validator = new JwtValidator(new TestTokenProvider(false));
    String token = createToken(ISSUER, SUBJECT, AUDIENCE, null, Instant.now().plusSeconds(300));

    assertNull(validator.validateJwt(null, token));
  }

  private static String createToken(String issuer, String subject, String audience, String tokenUse, Instant expiresAt) {
    JWTCreator.Builder builder =
        JWT.create()
            .withKeyId(KEY_ID)
            .withIssuer(issuer)
            .withSubject(subject)
            .withAudience(audience)
            .withExpiresAt(Date.from(expiresAt));
    if (tokenUse != null) {
      builder.withClaim("token_use", tokenUse);
    }
    return builder.sign(signingAlgorithm);
  }

  private static String encode(BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes.length > 1 && bytes[0] == 0) {
      bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
    }
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static final class TestTokenProvider implements TokenProvider {

    private final boolean requireIdToken;

    private TestTokenProvider(boolean requireIdToken) {
      this.requireIdToken = requireIdToken;
    }

    @Override
    public JwkProvider getJwkProvider() {
      return keyId -> jwk;
    }

    @Override
    public String getIssuer() {
      return ISSUER;
    }

    @Override
    public String getAudience() {
      return AUDIENCE;
    }

    @Override
    public boolean isValidToken(DecodedJWT jwt) {
      return !requireIdToken || "id".equals(jwt.getClaim("token_use").asString());
    }
  }
}
