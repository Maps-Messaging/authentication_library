/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.jaas;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;

public class AwsCognitoLoginModule extends BaseLoginModule {

  private String userPoolId;
  private String clientId;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    userPoolId = (String) options.get("userPoolId");
    clientId = (String) options.get("clientId");
  }

  public boolean validate(String username, char[] password) throws LoginException {

    try (CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.create()) {
      AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
          .authFlow("ADMIN_NO_SRP_AUTH")
          .clientId(clientId)
          .userPoolId(userPoolId)
          .authParameters(
              Map.of(
                  "USERNAME", username,
                  "PASSWORD", new String(password)
              )
          )
          .build();

      AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);
      AuthenticationResultType authResult = authResponse.authenticationResult();
      // If the above code executes without throwing an exception,
      // the JWT token is valid for the given user
      return true;
    } catch (NotAuthorizedException e) {
      // If the token is not valid or the user is not authorized, the above code will throw a NotAuthorizedException
      LoginException exception = new LoginException("Not authorised exception raised");
      exception.initCause(e);
      throw exception;
    }
  }

}
