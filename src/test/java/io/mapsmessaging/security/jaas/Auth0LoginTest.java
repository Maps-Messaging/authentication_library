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

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class Auth0LoginTest {

  private static Properties properties;
  private static String domain;

  @BeforeAll
  static void loadProperties() throws IOException {
    properties = PropertiesLoader.getProperties("Auth0.properties");
    domain = properties.getProperty("auth0Domain");
  }

  Map<String, String> getOptions() {
    Map<String, String> options = new LinkedHashMap<>();
    options.put("auth0Domain", domain);
    return options;
  }

  @Test
  void basicValidation() throws IOException, InterruptedException, LoginException {
    if (properties.isEmpty()) {
      return;
    }
    String body = (String) properties.get("requestBody");

    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create("https://" + domain + "/oauth/token"))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();

    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

    JsonObject jsonObject = JsonParser.parseString(response.body()).getAsJsonObject();
    char[] access_token = jsonObject.get("access_token").getAsString().toCharArray();


    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler("oNnOEXu8CsIYYxpu56ADpfm4Ma8Z1GNt", access_token, "");
    Subject subject = new Subject();
    LoginModule loginModule = new Auth0JwtLoginModule();
    loginModule.initialize(subject, clientCallbackHandler, null, getOptions());

    Assertions.assertTrue(loginModule.login());
    Assertions.assertTrue(loginModule.commit());
    Assertions.assertEquals("auth0", ((Auth0JwtLoginModule) loginModule).getDomain());
  }

  @Test
  void basicExceptionalidation() {
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler("Auth0", "BadToken".toCharArray(), "");
    Subject subject = new Subject();
    LoginModule loginModule = new Auth0JwtLoginModule();
    loginModule.initialize(subject, clientCallbackHandler, null, getOptions());

    Assertions.assertThrowsExactly(JWTDecodeException.class, loginModule::login);
  }
}
