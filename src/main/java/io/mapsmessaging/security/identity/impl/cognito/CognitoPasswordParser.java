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

package io.mapsmessaging.security.identity.impl.cognito;

import static io.mapsmessaging.security.identity.JwtHelper.isJwt;

import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.jaas.aws.AwsAuthHelper;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

public class CognitoPasswordParser implements PasswordParser {

  private final CognitoAuth cognitoAuth;
  private final String username;

  private byte[] computedPassword;

  public CognitoPasswordParser(String username, CognitoAuth cognitoAuth) {
    this.cognitoAuth = cognitoAuth;
    this.username = username;
  }

  @Override
  public PasswordParser create(String password) {
    return null;
  }

  @Override
  public String getKey() {
    return null;
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    try {
      String passwordString = new String(password);

      // Login based on the JWT being passed in
      if (isJwt(passwordString)) {
        if (validateForJWT(cognitoAuth.getCognitoClient(), username, passwordString)) {
          computedPassword = password;
          return password;
        }
        return new byte[0];
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
        computedPassword = password;
        return password;
      }
    } catch (Exception ex) {
      // todo log
    }
    // If the above code executes without throwing an exception,
    // the JWT token is valid for the given user
    computedPassword = new byte[10];
    Arrays.fill(computedPassword, (byte) 0xff);
    return new byte[0];
  }

  @Override
  public byte[] getPassword() {
    return computedPassword;
  }

  public String generateSecretHash(String username) throws NoSuchAlgorithmException, InvalidKeyException {
    return AwsAuthHelper.generateSecretHash(cognitoAuth.getAppClientId(), cognitoAuth.getAppClientSecret(), username);
  }

  private boolean validateForJWT(CognitoIdentityProviderClient cognitoClient, String username, String jwt) {
    GetUserRequest getUserRequest = GetUserRequest.builder()
        .accessToken(jwt)
        .build();

    // Call GetUser to validate the token
    GetUserResponse getUserResponse = cognitoClient.getUser(getUserRequest);

    // Retrieve the username from the GetUserResponse
    return username.equals(getUserResponse.username());
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public char[] getFullPasswordHash() {
    return new char[0];
  }

  @Override
  public String getName() {
    return "cognito";
  }
}
