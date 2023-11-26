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

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.sun.security.auth.UserPrincipal;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Map;

public class Auth0JwtLoginModule extends BaseLoginModule {

  private String domain;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    domain = (String) options.get("auth0Domain");
  }

  @Override
  protected boolean validate(String username, char[] password) throws LoginException {
    try {
      String token = new String(password);
      JwkProvider provider = new UrlJwkProvider("https://" + domain + "/");
      DecodedJWT jwt = JWT.decode(token);
      Jwk jwk = provider.get(jwt.getKeyId());
      Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
      JWTVerifier verifier = JWT.require(algorithm)
          .withIssuer("https://" + domain + "/")
          .build();
      DecodedJWT verifiedJwt = verifier.verify(token);
      LocalDate expires = verifiedJwt.getExpiresAt().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
      LocalDate now = LocalDate.now();
      if (expires.isBefore(now)) {
        throw new LoginException("Token expired on " + expires);
      }
      // Need to add token information into the subject
      String tokenUser = jwt.getSubject();
      if (tokenUser.contains("@")) {
        tokenUser = tokenUser.substring(0, tokenUser.indexOf("@"));
      }
      if (username.equals(tokenUser)) {
        userPrincipal = new UserPrincipal(username);
        return true;
      }
      return false;
    } catch (JwkException e) {
      LoginException loginException = new LoginException("Java web token exception");
      loginException.initCause(e);
      throw loginException;
    }
  }
}
