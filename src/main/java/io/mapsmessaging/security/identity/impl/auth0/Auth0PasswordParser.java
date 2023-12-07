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
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.net.Response;
import com.auth0.net.TokenRequest;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import lombok.Getter;

public class Auth0PasswordParser implements PasswordParser {

  private final Auth0Auth auth;
  private final String username;
  @Getter private TokenHolder token;

  private byte[] computedPassword = new byte[0];

  public Auth0PasswordParser() {
    auth = null;
    username = "";
  }

  public Auth0PasswordParser(String username, Auth0Auth auth) {
    this.auth = auth;
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
    if (auth == null) {
      return new byte[0];
    }
    String passwordString = new String(password);
    if (isJwt(passwordString)) {
      try {
        if (validateJwt(passwordString)) {
          computedPassword = password;
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
        token = holder.getBody();
        computedPassword = password;
        return computedPassword;
      }
    } catch (Auth0Exception e) {
      computedPassword = new byte[12];
      Arrays.fill(computedPassword, (byte) 0xff);
      e.printStackTrace();
      // ToDo log
    }
    return new byte[0];
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public byte[] getPassword() {
    return computedPassword;
  }

  @Override
  public char[] getFullPasswordHash() {
    return new char[0];
  }

  @Override
  public String getName() {
    return "auth0";
  }

  private boolean validateJwt(String token) throws JwkException {
    JwkProvider provider = new UrlJwkProvider("https://" + auth.getAuth0Domain() + "/");
    DecodedJWT jwt = JWT.decode(token);
    Jwk jwk = provider.get(jwt.getKeyId());
    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
    JWTVerifier verifier =
        JWT.require(algorithm).withIssuer("https://" + auth.getAuth0Domain() + "/").build();
    DecodedJWT verifiedJwt = verifier.verify(token);
    return validate(verifiedJwt);
  }

  private boolean validate(DecodedJWT verifiedJwt) {
    LocalDate expires =
        verifiedJwt.getExpiresAt().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    LocalDate now = LocalDate.now();
    if (expires.isBefore(now)) {
      return false;
    }
    // Need to add token information into the subject
    String tokenUser = verifiedJwt.getSubject();
    if (tokenUser.contains("@")) {
      tokenUser = tokenUser.substring(0, tokenUser.indexOf("@"));
    }
    return (username.equals(tokenUser));
  }
}
