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

package io.mapsmessaging.security.jaas;

import static io.mapsmessaging.security.jaas.aws.AwsAuthHelper.generateSecretHash;
import static io.mapsmessaging.security.jaas.aws.AwsAuthHelper.getGroups;
import static io.mapsmessaging.security.jaas.aws.AwsAuthHelper.isJwt;

import io.mapsmessaging.security.identity.principals.AuthHandlerPrincipal;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;

public class AwsCognitoLoginModule extends BaseLoginModule {

  private String userPoolId;
  private String clientId;
  private String accessKey;
  private String accessSecret;

  private String secretAccessKey;
  private Region region;

  private List<String> groupList;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    userPoolId =(String) options.get("userPoolId");
    accessKey = (String) options.get("accessKey");
    accessSecret = (String) options.get("aimSecretKey");

    clientId = (String) options.get("clientId");
    secretAccessKey = (String) options.get("secretAccessKey");

    region = Region.of ((String) options.get("region"));
  }


  public boolean validate(String username, char[] password) throws LoginException {

    // Create AWS credentials provider
    AwsBasicCredentials credentials = AwsBasicCredentials.create(accessKey, accessSecret);
    StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(credentials);

    try (CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder().credentialsProvider(credentialsProvider).region(region).build()) {
      String secretHash = generateSecretHash(clientId, secretAccessKey, username);
      String passwordString = new String(password);

      // Login based on the JWT being passed in
      if(isJwt(passwordString)){
        return validateForJWT(cognitoClient, username, passwordString);
      }

      // Login based on user/password
      AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
          .authFlow("ADMIN_NO_SRP_AUTH")
          .clientId(clientId)
          .userPoolId(userPoolId)
          .authParameters(
              Map.of(
                  "USERNAME", username,
                  "PASSWORD", new String(password),
                  "SECRET_HASH", secretHash
              )
          )
          .build();

      AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);
      AuthenticationResultType authResult = authResponse.authenticationResult();
      if(authResult != null){
        groupList = getGroups(authResult.accessToken(), region.id(), userPoolId);
        return true;
      }
      // If the above code executes without throwing an exception,
      // the JWT token is valid for the given user
      return false;
    } catch (NotAuthorizedException | NoSuchAlgorithmException | InvalidKeyException e) {
      // If the token is not valid or the user is not authorized, the above code will throw a NotAuthorizedException
      LoginException exception = new LoginException("Not authorised exception raised");
      exception.initCause(e);
      throw exception;
    }
  }

  @Override
  public boolean commit() {
    boolean res = super.commit();
    if(res && groupList != null){
      // Add known groups here
      for(String group:groupList){
        subject.getPrincipals().add(new GroupPrincipal(group));
      }
      subject.getPrincipals().add(new AuthHandlerPrincipal("Aws:Cognito"));
    }
    return res;
  }

  private boolean validateForJWT(CognitoIdentityProviderClient cognitoClient, String username, String jwt){
    GetUserRequest getUserRequest = GetUserRequest.builder()
        .accessToken(jwt)
        .build();

    // Call GetUser to validate the token
    GetUserResponse getUserResponse = cognitoClient.getUser(getUserRequest);

    // Retrieve the username from the GetUserResponse
    return username.equals(getUserResponse.username());
  }



}
