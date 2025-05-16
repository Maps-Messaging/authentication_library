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

import io.mapsmessaging.security.sasl.ClientCallbackHandler;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CognitoLoginTest {

  static Properties properties;

  @BeforeAll
  static void loadProperties() throws IOException {
    properties  = PropertiesLoader.getProperties("cognito.properties");

  }

  Map<String, String> getOptions() {

    Map<String, String> options = new LinkedHashMap<>();
    options.put("region", properties.getProperty("region"));
    options.put("userPoolId",  properties.getProperty("userPoolId"));

    // AIM Keys
    options.put("accessKeyId", properties.getProperty("accessKeyId"));
    options.put("secretAccessKey",properties.getProperty("secretAccessKey"));

    // Cognito App Access Id
    options.put("appClientId", properties.getProperty("appClientId"));
    options.put("appClientSecret", properties.getProperty("appClientSecret"));

    return options;
  }

  @Test
  void basicValidation() throws  LoginException {
    if (properties == null || properties.isEmpty()) {
      return;
    }
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler("maps.test", "testPassword01!".toCharArray(), "");
    Subject subject = new Subject();
    AwsCognitoLoginModule loginModule = new AwsCognitoLoginModule();
    loginModule.initialize(subject, clientCallbackHandler, null, getOptions());
    Assertions.assertTrue(loginModule.login());
    Assertions.assertTrue(loginModule.commit());
    Assertions.assertEquals("cognito", loginModule.getDomain() );
  }

  @Test
  void basicExceptionalidation() {
    if (properties == null || properties.isEmpty()) {
      return;
    }
    ClientCallbackHandler clientCallbackHandler = new ClientCallbackHandler("maps.test", "BadToken".toCharArray(), "");
    Subject subject = new Subject();
    LoginModule loginModule = new AwsCognitoLoginModule();
    loginModule.initialize(subject, clientCallbackHandler, null, getOptions());
    Assertions.assertThrowsExactly(LoginException.class, loginModule::login);
  }

}
