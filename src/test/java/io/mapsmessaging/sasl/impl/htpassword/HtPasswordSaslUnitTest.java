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

package io.mapsmessaging.sasl.impl.htpassword;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.sasl.impl.BaseSasl;
import io.mapsmessaging.security.auth.PasswordParser;
import io.mapsmessaging.security.auth.PasswordParserFactory;
import io.mapsmessaging.security.sasl.impl.htpasswd.HashType;
import io.mapsmessaging.security.sasl.impl.htpasswd.HtPasswd;
import java.util.HashMap;
import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HtPasswordSaslUnitTest extends BaseSasl {

  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "amqp";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth";

  @Test
  public void checkMd5Hash() {
    testHashing("$apr1$po9cazbx$JG5SMaTSVYrtFlYQb821M.", "This is an md5 password");
  }

  @Test
  public void checkBcryptHash() {
    testHashing("$2y$10$BzVXd/hbkglo7bRLVZwYEu/45Uy24FsoZBHEaJqi690AJzIOV/Q5u", "This is an bcrypt password");
  }

  private void testHashing(String passwordHashString, String rawPassword){
    //
    // We parse the password string to extract the public SALT, so we can pass to the client
    //
    PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(passwordHashString);


    // This would be done on the client side of this
    byte[] hash = passwordParser.computeHash(rawPassword.getBytes(), passwordParser.getSalt(), passwordParser.getCost());

    // The result should be that the hash = password + salt hashed should match what the server has
    Assertions.assertArrayEquals(passwordHashString.toCharArray(), new String(hash).toCharArray());

  }

  @ParameterizedTest
  @ValueSource(strings = {"DIGEST-MD5", "CRAM-MD5"})
  public void simpleDigestNonSaltValidTest(String mechanism) throws SaslException {
    testMechanism(mechanism, "fred2@google.com", "This is a random password", HashType.SHA1);
  }

  @ParameterizedTest
  @ValueSource(strings = {"SCRAM-BCRYPT-SHA1", "SCRAM-BCRYPT-SHA256", "SCRAM-BCRYPT-SHA512"})
  public void simpleScramValidTest(String mechanism) throws SaslException {
    testMechanism(mechanism, "test3", "This is an bcrypt password", HashType.PLAIN);
  }

  @ParameterizedTest
  @ValueSource(strings = {"DIGEST-MD5", "CRAM-MD5"})
  public void simpleWrongPasswordTest(String mechanism) {
    Assertions.assertThrowsExactly(SaslException.class, () -> testMechanism(mechanism, "fred2@google.com", "This is a wrong password", HashType.SHA1));
  }

  void testMechanism(String mechanism, String user, String password, HashType type) throws SaslException {
    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);
    createServer(new HtPasswd("./src/test/resources/.htpassword"), mechanism, PROTOCOL, SERVER_NAME, props);
    createClient(
        user,
        password,
        type,
        new String[]{mechanism},
        PROTOCOL,
        AUTHORIZATION_ID,
        SERVER_NAME,
        props
    );
    simpleValidation();
  }

  void simpleValidation() throws SaslException {
    assertNotNull(saslServer, "This should not be null");
    assertNotNull(saslClient, "This should not be null");
    runAuth();
    assertTrue(saslServer.isComplete());
    assertTrue(saslClient.isComplete());

    String qop = (String) saslClient.getNegotiatedProperty(Sasl.QOP);
    Assertions.assertTrue(qop.startsWith("auth"), "We should have an authorised SASL session");
  }
}
