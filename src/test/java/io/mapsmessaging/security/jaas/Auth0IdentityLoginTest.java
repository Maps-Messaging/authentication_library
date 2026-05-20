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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.mapsmessaging.security.access.AuthContext;
import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import javax.security.auth.spi.LoginModule;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.*;

public class Auth0IdentityLoginTest extends BaseIdentity {
  private static Properties properties;

  @BeforeAll
  static void loadProperties() {
    try {
      properties = PropertiesLoader.getProperties("Auth0Identity.properties");
    } catch (IOException e) {
    }
    if (properties == null) {
      properties = new Properties();
    }
  }

  @BeforeEach
  void waitForGlobalRate() throws InterruptedException {
    TimeUnit.SECONDS.sleep(2); // Auth0 has a rate limit
  }

  Map<String, String> getOptions() {
    Map<String, String> map =
        new LinkedHashMap<>(
            properties.entrySet().stream()
                .collect(
                    LinkedHashMap::new,
                    (m, e) -> m.put(e.getKey().toString(), e.getValue().toString()),
                    Map::putAll));
    map.put("identityName", "Auth0");
    return map;
  }

  @Override
  @Test
  void noPasswordFileTestTest() {}

  @Override
  String getUser() {
    return "admin@mapsmessaging.io";
  }

  @Override
  char[] getPassword() {
    return "testPassword01!".toCharArray();
  }

  @Test
  void simpleJwtLoginTest() throws Exception {
    Auth0Client auth0Client = new Auth0Client();
    char[] token = auth0Client.authenticateAndGetToken().toCharArray();
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), token, "",new AuthContext("localhost", "test", "test"));
    LoginModule module = createLoginModule(clientCallbackHandler);
    Assertions.assertTrue(module.login());
    Assertions.assertTrue(subject.getPrincipals().isEmpty());
    Assertions.assertTrue(module.commit());
    Assertions.assertFalse(subject.getPrincipals().isEmpty());
  }

  public class Auth0Client {

    public String authenticateAndGetToken() throws Exception {
      Gson gson = new Gson();
      String url = "https://" + properties.get("domain") + "/oauth/token";
      try (CloseableHttpClient client = HttpClients.createDefault()) {
        HttpPost httpPost = new HttpPost(url);

        JsonObject json = new JsonObject();
        String clientId = properties.getProperty("clientId");
        if (clientId != null) {
          json.addProperty("client_id", clientId);
        }

        String clientSecret = properties.getProperty("clientSecret");
        if (clientSecret != null) {
          json.addProperty("client_secret", clientSecret);
        }

        json.addProperty("grant_type", "password"); // overwrites "client_credentials"
        json.addProperty("username", getUser());
        json.addProperty("password", new String(getPassword()));

        StringEntity entity = new StringEntity(gson.toJson(json), StandardCharsets.UTF_8);
        httpPost.setEntity(entity);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");

        var response = client.execute(httpPost);
        String result = EntityUtils.toString(response.getEntity());

        JsonObject responseJson = JsonParser.parseString(result).getAsJsonObject();
        return responseJson.get("id_token").getAsString();

      }
    }
  }
}