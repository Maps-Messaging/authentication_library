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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

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


  @Override
  @Test
  void noPasswordFileTestTest() {
  }

  @Override
  String getUser() {
    return "maps.test";
  }

  @Override
  String getPassword() {
    return "testPassword01!";
  }
}