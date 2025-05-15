/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.identity.impl.external;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.ZoneId;

public class JwtValidator {

  private final TokenProvider tokenProvider;

  public JwtValidator(TokenProvider tokenProvider) {
    this.tokenProvider = tokenProvider;
  }

  public DecodedJWT validateJwt(String username, String token) throws JwkException {
    DecodedJWT decodedJwt = JWT.decode(token);
    String issuer = decodedJwt.getIssuer();
    JwkProvider provider = tokenProvider.getJwkProvider(issuer);

    Jwk jwk = provider.get(decodedJwt.getKeyId());
    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

    JWTVerifier verifier = JWT.require(algorithm).withIssuer(issuer).build();
    DecodedJWT verifiedJwt = verifier.verify(token);
    if (validate(username, verifiedJwt)) {
      return verifiedJwt;
    }
    return verifiedJwt;
  }

  private boolean validate(String username, DecodedJWT verifiedJwt) {
    LocalDate expires =
        verifiedJwt.getExpiresAt().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    LocalDate now = LocalDate.now();
    if (expires.isBefore(now)) {
      return false;
    }
    String name = verifiedJwt.getClaim("name").asString();
    return (username.equals(name));
  }
}
