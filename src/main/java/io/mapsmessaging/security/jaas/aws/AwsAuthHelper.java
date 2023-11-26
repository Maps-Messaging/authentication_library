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

package io.mapsmessaging.security.jaas.aws;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

public class AwsAuthHelper {

  public static List<String> getGroups(String token, String region, String userPoolId) {
    RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(region, userPoolId);
    Algorithm algorithm = Algorithm.RSA256(keyProvider);
    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
    DecodedJWT decodedJWT = jwtVerifier.verify(token);
    Claim groups = decodedJWT.getClaim("cognito:groups");
    return groups.asList(String.class);
  }


  public static boolean isJwt(String token) {
    // Check if the token has three parts (header, payload, signature)
    String[] tokenParts = token.split("\\.");
    if (tokenParts.length != 3) {
      return false;
    }

    // Decode the header and payload and check if they are valid Base64 strings
    try {
      Base64.getUrlDecoder().decode(tokenParts[0]);
      Base64.getUrlDecoder().decode(tokenParts[1]);
    } catch (IllegalArgumentException e) {
      return false;
    }
    return true;
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
