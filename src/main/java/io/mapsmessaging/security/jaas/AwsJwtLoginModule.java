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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.net.MalformedURLException;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

public class AwsJwtLoginModule extends BaseLoginModule {

  private String region;
  private String poolId;
  private String clientId;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    region = (String) options.get("region");
    poolId = (String) options.get("poolId");
    clientId = (String) options.get("clientId");
  }

  @Override
  protected boolean validate(String username, char[] password) throws LoginException {
    String token = new String(password);
    try {
      RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(region, poolId);
      Algorithm algorithm = Algorithm.RSA256(keyProvider);
      JWTVerifier jwtVerifier = JWT.require(algorithm)
          .withAudience(clientId)
          .build();
      jwtVerifier.verify(token);
    } catch (MalformedURLException e) {
      LoginException loginException = new LoginException("Failed to authenticate via AWS");
      loginException.initCause(e);
      throw loginException;
    }
    // Need to validate
    return true;
  }
}
