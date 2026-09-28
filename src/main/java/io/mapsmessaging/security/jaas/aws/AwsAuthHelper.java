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

package io.mapsmessaging.security.jaas.aws;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AwsAuthHelper {

  private AwsAuthHelper(){}

  public static List<String> getGroups(String token, String region, String userPoolId, String appClientId) throws IOException {
    return getGroups(validateAccessToken(token, region, userPoolId, appClientId));
  }

  public static DecodedJWT validateAccessToken(String token, String region, String userPoolId, String appClientId) throws IOException {
    RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(region, userPoolId);
    String issuer = "https://cognito-idp." + region + ".amazonaws.com/" + userPoolId;
    return validateAccessToken(token, issuer, appClientId, keyProvider);
  }

  static DecodedJWT validateAccessToken(String token, String issuer, String appClientId, RSAKeyProvider keyProvider) {
    Algorithm algorithm = Algorithm.RSA256(keyProvider);
    JWTVerifier jwtVerifier =
        JWT.require(algorithm)
            .withIssuer(issuer)
            .withClaim("token_use", "access")
            .withClaim("client_id", appClientId)
            .withClaimPresence("sub")
            .withClaimPresence("exp")
            .withClaimPresence("iat")
            .build();
    return jwtVerifier.verify(token);
  }

  public static List<String> getGroups(DecodedJWT decodedJWT) {
    Claim groups = decodedJWT.getClaim("cognito:groups");
    List<String> groupList = groups.asList(String.class);
    return groupList == null ? Collections.emptyList() : groupList;
  }


  public static String generateSecretHash(String clientId, String clientSecret, String username) throws NoSuchAlgorithmException, InvalidKeyException {
    String message = username + clientId;
    byte[] key = clientSecret.getBytes(StandardCharsets.UTF_8);
    byte[] data = message.getBytes(StandardCharsets.UTF_8);

    SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA256");

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(signingKey);
    byte[] hmacResult = mac.doFinal(data);


    // Encode the result in base64
    return Base64.getEncoder().encodeToString(hmacResult);
  }

}
