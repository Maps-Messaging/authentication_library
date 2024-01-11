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

package io.mapsmessaging.security.jaas;

import java.util.Properties;
import org.junit.jupiter.api.Disabled;

@Disabled
public class Auth0IdentityLoginTest { // extends BaseIdentity {
  private static Properties properties;
  /*

   @BeforeAll
   static void loadProperties() throws IOException {
     try {
       properties = PropertiesLoader.getProperties("Auth0Identity.properties");
     } catch (IOException e) {
     }
     if (properties == null) {
       properties = new Properties();
     }
   }

   Map<String, String> getOptions() {
     Map<String, String> map = new LinkedHashMap<>(properties.entrySet().stream().collect(
         LinkedHashMap::new,
         (m, e) -> m.put(e.getKey().toString(), e.getValue().toString()),
         Map::putAll));
     map.put("identityName", "Auth0");
     return map;
   }


   @Override
   @Test
   void noPasswordFileTestTest() {
   }

   @Override
   @Test
   void simpleLoginTest() throws LoginException {
   }


   @Override
   String getUser() {
     return "admin@mapsmessaging.io";
   }

   @Override
   String getPassword() {
     return "testPassword01!";
   }

   @Test
   void simpleJwtLoginTest() throws Exception {
     Auth0Client auth0Client = new Auth0Client();
     String token = auth0Client.authenticateAndGetToken();
     ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler(getUser(), token, "");
     LoginModule module = createLoginModule(clientCallbackHandler);
     Assertions.assertTrue(module.login());
     Assertions.assertTrue(subject.getPrincipals().isEmpty());
     Assertions.assertTrue(module.commit());
     Assertions.assertFalse(subject.getPrincipals().isEmpty());
   }

   public class Auth0Client {

     public String authenticateAndGetToken() throws Exception {
       String url = "https://" + properties.get("domain") + "/oauth/token";
       try (CloseableHttpClient client = HttpClients.createDefault()) {
         HttpPost httpPost = new HttpPost(url);

         String json =
             new JSONObject()
                 .put("client_id", properties.get("clientId"))
                 .put("client_secret", properties.get("clientSecret"))
                 .put("grant_type", "client_credentials")
                 .put("grant_type", "password") // Note: using the Resource Owner Password Grant
                 .put("username", getUser())
                 .put("password", getPassword())
                 .toString();

         StringEntity entity = new StringEntity(json);
         httpPost.setEntity(entity);
         httpPost.setHeader("Accept", "application/json");
         httpPost.setHeader("Content-type", "application/json");

         var response = client.execute(httpPost);
         String result = EntityUtils.toString(response.getEntity());
         JSONObject jsonObj = new JSONObject(result);
         return jsonObj.getString("id_token");
       }
     }
   }

  */
}
