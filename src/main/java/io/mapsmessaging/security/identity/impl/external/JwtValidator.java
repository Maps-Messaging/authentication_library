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

package io.mapsmessaging.security.identity.impl.external;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.security.interfaces.RSAPublicKey;

public class JwtValidator {

  private final TokenProvider tokenProvider;

  public JwtValidator(TokenProvider tokenProvider) {
    this.tokenProvider = tokenProvider;
  }

  public DecodedJWT validateJwt(String expectedSubject, String token) throws JwkException {
    if (expectedSubject == null || expectedSubject.isBlank()) {
      return null;
    }

    DecodedJWT decodedJwt = JWT.decode(token);
    JwkProvider provider = tokenProvider.getJwkProvider();

    Jwk jwk = provider.get(decodedJwt.getKeyId());
    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

    JWTVerifier verifier =
        JWT.require(algorithm)
            .withIssuer(tokenProvider.getIssuer())
            .withAudience(tokenProvider.getAudience())
            .withSubject(expectedSubject)
            .build();
    DecodedJWT verifiedJwt = verifier.verify(token);
    return tokenProvider.isValidToken(verifiedJwt) ? verifiedJwt : null;
  }
}
