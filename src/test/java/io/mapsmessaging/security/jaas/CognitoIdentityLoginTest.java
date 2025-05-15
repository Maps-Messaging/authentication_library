/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.jaas;

import io.mapsmessaging.security.identity.principals.JwtPrincipal;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CognitoIdentityLoginTest extends BaseIdentity {
  private static Properties properties;


  @BeforeAll
  static void loadProperties() throws IOException {
    properties = PropertiesLoader.getProperties("cognito.properties");
  }

  Map<String, String> getOptions() {
    Map<String, String> map = new LinkedHashMap<>(properties.entrySet().stream().collect(
        LinkedHashMap::new,
        (m, e) -> m.put(e.getKey().toString(), e.getValue().toString()),
        Map::putAll));
    map.put("identityName", "Cognito");
    return map;
  }

  protected void validateSubject(Subject subject) {
    super.validateSubject(subject);
    Set<JwtPrincipal> jwtPrincipals = subject.getPrincipals(JwtPrincipal.class);
    for (JwtPrincipal jwtPrincipal : jwtPrincipals) {
      Assertions.assertEquals(1, jwtPrincipal.getAudience().size());
      Assertions.assertNotNull(jwtPrincipal.getExpires());
      Assertions.assertNotNull(jwtPrincipal.getIssued());
      Assertions.assertNotNull(jwtPrincipal.getIssuer());
      Assertions.assertFalse(jwtPrincipal.getClaims().isEmpty());

    }
  }

  @Override
  @Test
  void noPasswordFileTestTest() {
  }

  @Override
  String getUser() {
    return "maps.test";
  }

  @Override
  char[] getPassword() {
    return "testPassword01!".toCharArray();
  }
}