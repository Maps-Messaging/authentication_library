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

package io.mapsmessaging.security.identity.impl.cognito;

import static io.mapsmessaging.security.identity.JwtHelper.isJwt;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import io.mapsmessaging.security.identity.impl.external.JwtPasswordHasher;
import io.mapsmessaging.security.identity.impl.external.JwtValidator;
import io.mapsmessaging.security.identity.impl.external.TokenProvider;
import io.mapsmessaging.security.jaas.aws.AwsAuthHelper;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;

public class CognitoPasswordHasher extends JwtPasswordHasher implements TokenProvider {

  private final CognitoAuth cognitoAuth;
  private final String username;
  private final CognitoIdentityEntry identityEntry;

  public CognitoPasswordHasher(
      String username, CognitoAuth cognitoAuth, CognitoIdentityEntry identityEntry) {
    this.cognitoAuth = cognitoAuth;
    this.username = username;
    this.identityEntry = identityEntry;
  }

  @Override
  public byte[] transformPassword(byte[] password, byte[] salt, int cost) {
    try {
      String passwordString = new String(password);

      // Login based on the JWT being passed in
      if (isJwt(passwordString)) {
        JwtValidator validator = new JwtValidator(this);
        jwt = validator.validateJwt(username, passwordString);
        computedPassword = password;
        success();
        return password;
      }
      // Login based on user/password
      String secretHash = generateSecretHash(username);
      AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
          .authFlow("ADMIN_NO_SRP_AUTH")
          .clientId(cognitoAuth.getAppClientId())
          .userPoolId(cognitoAuth.getUserPoolId())
          .authParameters(
              Map.of(
                  "USERNAME", username,
                  "PASSWORD", new String(password),
                  "SECRET_HASH", secretHash
              )
          )
          .build();


      AdminInitiateAuthResponse authResponse = cognitoAuth.getCognitoClient().adminInitiateAuth(authRequest);
      AuthenticationResultType authResult = authResponse.authenticationResult();
      if (authResult != null) {
        JwtValidator validator = new JwtValidator(this);
        jwt = validator.validateJwt(username, authResult.idToken());
        computedPassword = password;
        success();
        return password;
      }
    } catch (Exception ex) {
      // This is an invalid user, lets not log entries since DDOS lets just fail it
    }
    // If the above code executes without throwing an exception,
    // the JWT token is valid for the given user
    computedPassword = new byte[10];
    Arrays.fill(computedPassword, (byte) 0xff);
    return new byte[0];
  }


  public String generateSecretHash(String username) throws NoSuchAlgorithmException, InvalidKeyException {
    return AwsAuthHelper.generateSecretHash(cognitoAuth.getAppClientId(), cognitoAuth.getAppClientSecret(), username);
  }

  private void success() {
    if (cognitoAuth != null) {
      if (jwt != null) {
        String sub = jwt.getClaim("sub").asString();
        if (sub != null) identityEntry.setUuid(sub);
      }
      cognitoAuth.authorised(identityEntry);
    }
  }


  @Override
  public String getName() {
    return "cognito";
  }

  @Override
  public JwkProvider getJwkProvider(String issuer) {
    return new UrlJwkProvider(
        "https://cognito-idp."
            + cognitoAuth.getRegionName()
            + ".amazonaws.com/"
            + cognitoAuth.getUserPoolId());
  }
}
