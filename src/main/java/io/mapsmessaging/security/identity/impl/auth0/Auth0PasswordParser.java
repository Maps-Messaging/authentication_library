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

package io.mapsmessaging.security.identity.impl.auth0;

import static io.mapsmessaging.security.identity.JwtHelper.isJwt;

import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.jwk.*;
import com.auth0.net.Response;
import com.auth0.net.TokenRequest;
import io.mapsmessaging.security.identity.impl.external.JwtPasswordParser;
import io.mapsmessaging.security.identity.impl.external.JwtValidator;
import io.mapsmessaging.security.identity.impl.external.TokenProvider;
import java.util.Arrays;

public class Auth0PasswordParser extends JwtPasswordParser implements TokenProvider {

  private final Auth0Auth auth;
  private final Auth0IdentityEntry identityEntry;
  private final String username;

  public Auth0PasswordParser() {
    auth = null;
    username = "";
    identityEntry = null;
  }

  public Auth0PasswordParser(String username, Auth0Auth auth, Auth0IdentityEntry identityEntry) {
    this.auth = auth;
    this.username = username;
    this.identityEntry = identityEntry;
  }

  @Override
  public String getName() {
    return "auth0";
  }

  @Override
  public byte[] computeHash(byte[] password, byte[] salt, int cost) {
    if (auth == null) {
      return new byte[0];
    }
    String passwordString = new String(password);
    if (isJwt(passwordString)) {
      try {
        JwtValidator validator = new JwtValidator(this);
        jwt = validator.validateJwt(username, passwordString);
        if (jwt != null) {
          computedPassword = password;
          success();
          return computedPassword;
        }
      } catch (JwkException e) {
        // todo Log this
      }
      return new byte[0];
    }

    try {
      TokenRequest request =
          auth.getAuthAPI()
              .login(username, passwordString.toCharArray())
              .setScope("openid profile email");
      Response<TokenHolder> holder = request.execute();

      if (holder.getStatusCode() == 200) {
        TokenHolder token = holder.getBody();
        String idToken = token.getIdToken();
        JwtValidator validator = new JwtValidator(this);
        jwt = validator.validateJwt(username, idToken);
        computedPassword = password;
        success();
        return computedPassword;
      }
    } catch (Auth0Exception | JwkException e) {
      computedPassword = new byte[12];
      Arrays.fill(computedPassword, (byte) 0xff);
      // ToDo log
    }
    return new byte[0];
  }

  private void success() {
    if (auth != null) auth.authorised(identityEntry);
  }

  @Override
  public JwkProvider getJwkProvider(String issuer) {
    return new UrlJwkProvider("https://" + auth.getAuth0Domain() + "/");
  }
}
