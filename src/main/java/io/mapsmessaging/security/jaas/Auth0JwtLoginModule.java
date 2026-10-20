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

package io.mapsmessaging.security.jaas;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.access.AuthContext;
import io.mapsmessaging.security.identity.impl.external.JwtValidator;
import io.mapsmessaging.security.identity.impl.external.TokenProvider;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

public class Auth0JwtLoginModule extends BaseLoginModule implements TokenProvider {

  private String domain;
  private String audience;

  @Override
  public void initialize(
      Subject subject,
      CallbackHandler callbackHandler,
      Map<String, ?> sharedState,
      Map<String, ?> options) {
    super.initialize(subject, callbackHandler, sharedState, options);
    domain = (String) options.get("auth0Domain");
    audience = (String) options.get("audience");
  }

  @Override
  protected String getDomain() {
    return "auth0";
  }

  @Override
  protected boolean validate(String username, char[] password, AuthContext context) throws LoginException {
    try {
      String token = new String(password);
      String tokenSubject = JWT.decode(token).getSubject();
      JwtValidator validator = new JwtValidator(this);
      DecodedJWT verifiedJwt = validator.validateJwt(tokenSubject, token);
      if (verifiedJwt != null && username.equals(normalizeSubject(verifiedJwt.getSubject()))) {
        userPrincipal = new UserPrincipal(username);
        return true;
      }
      return false;
    } catch (JwkException | JWTVerificationException e) {
      LoginException loginException = new LoginException("Java web token exception");
      loginException.initCause(e);
      throw loginException;
    }
  }

  private String normalizeSubject(String subject) {
    String clientSuffix = "@clients";
    if (subject != null && subject.endsWith(clientSuffix)) {
      return subject.substring(0, subject.length() - clientSuffix.length());
    }
    return subject;
  }

  @Override
  public JwkProvider getJwkProvider() {
    return new UrlJwkProvider(getIssuer());
  }

  @Override
  public String getIssuer() {
    return "https://" + domain + "/";
  }

  @Override
  public String getAudience() {
    return audience;
  }
}
