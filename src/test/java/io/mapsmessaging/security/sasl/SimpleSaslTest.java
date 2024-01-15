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

package io.mapsmessaging.security.sasl;

import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.impl.apache.ApacheBasicAuth;
import io.mapsmessaging.security.identity.impl.unix.ShadowFileManager;
import io.mapsmessaging.security.passwords.hashes.sha.Sha1PasswordHasher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SimpleSaslTest extends BaseSasl {

  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "amqp";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth";

  @Test
  void simpleDebugTest() throws IOException {
    testMechanism("MAPS-TEST-10", "", "");
  }

  @ParameterizedTest
  @ValueSource(strings = {"PLAIN", "DIGEST-MD5", "CRAM-MD5"})
  void simpleDigestNonSaltValidTest(String mechanism) throws IOException {
    Sha1PasswordHasher passwordParser = new Sha1PasswordHasher();
    byte[] password = "This is a random password".getBytes(StandardCharsets.UTF_8);
    if (!mechanism.equalsIgnoreCase("PLAIN")) {
      password = passwordParser.transformPassword(password, null, 0);
    }
    testMechanism(mechanism, "fred2@google.com", new String(password));
  }

  @ParameterizedTest
  @ValueSource(strings = {"SCRAM-BCRYPT-SHA-512"})
  void simpleBCryptScramValidTest(String mechanism) throws IOException {
    testMechanism(mechanism, "test3", "This is an bcrypt password");
  }

  @ParameterizedTest
  @ValueSource(strings = {"SCRAM-SHA-512"})
  void simpleShadowScramValidTest(String mechanism) throws IOException {
    ShadowFileManager shadowFileManager = new ShadowFileManager("./src/test/resources/shadow");
//    testMechanism(shadowFileManager, mechanism, "test", "onewordpassword");
  }

  @ParameterizedTest
  @ValueSource(strings = {"DIGEST-MD5", "CRAM-MD5"})
  void simpleWrongPasswordTest(String mechanism) {
    Sha1PasswordHasher passwordParser = new Sha1PasswordHasher();
    byte[] password =
        passwordParser.transformPassword(
            "This is a wrong password".getBytes(StandardCharsets.UTF_8), null, 0);
    Assertions.assertThrowsExactly(SaslException.class, () -> testMechanism(mechanism, "fred2@google.com", new String(password)));
  }

  void testMechanism(String mechanism, String user, String password) throws IOException {
    testMechanism(new ApacheBasicAuth("./src/test/resources/apache/.htpassword", "./src/test/resources/apache/.htgroups"), mechanism, user, password);
  }

  void testMechanism(IdentityLookup identityLookup, String mechanism, String user, String password) throws IOException {
    SaslTester saslTester = new SaslTester();
    saslTester.testMechanism(identityLookup, mechanism, user, password);
  }

}
