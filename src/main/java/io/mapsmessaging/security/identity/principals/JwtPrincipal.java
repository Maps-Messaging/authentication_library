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

package io.mapsmessaging.security.identity.principals;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.security.Principal;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;
import lombok.Getter;

@Getter
public class JwtPrincipal implements Principal {

  private final LocalDateTime expires;
  private final LocalDateTime issued;
  private final Map<String, Claim> claims;
  private final List<String> audience;
  private final String issuer;

  public JwtPrincipal(DecodedJWT jwt) {
    expires = convertDateToLocalDateTime(jwt.getExpiresAt());
    issued = convertDateToLocalDateTime(jwt.getIssuedAt());
    claims = jwt.getClaims();
    audience = jwt.getAudience();
    issuer = jwt.getIssuer();
  }

  private static LocalDateTime convertDateToLocalDateTime(Date date) {
    return date.toInstant()
        .atZone(ZoneId.systemDefault()) // Replace with desired time zone if needed
        .toLocalDateTime();
  }

  public boolean isActive() {
    return issued.isAfter(LocalDateTime.now());
  }

  public String getName() {
    return "jwt";
  }

  public boolean hasExpired() {
    return expires.isAfter(LocalDateTime.now());
  }
}
