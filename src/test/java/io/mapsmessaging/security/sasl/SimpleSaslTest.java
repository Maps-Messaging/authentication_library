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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.impl.apache.ApacheBasicAuth;
import io.mapsmessaging.security.identity.impl.unix.ShadowFileManager;
import io.mapsmessaging.security.identity.parsers.sha.Sha1PasswordParser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
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
    Sha1PasswordParser passwordParser = new Sha1PasswordParser();
    byte[] password = "This is a random password".getBytes();
    if (!mechanism.equalsIgnoreCase("PLAIN")) {
      password = passwordParser.computeHash(password, null, 0);
    }
    testMechanism(mechanism, "fred2@google.com", new String(password));
  }

  @ParameterizedTest
  @ValueSource(strings = {"SCRAM-SHA-512"})
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
    Sha1PasswordParser passwordParser = new Sha1PasswordParser();
    byte[] password = passwordParser.computeHash("This is a wrong password".getBytes(), null, 0);
    Assertions.assertThrowsExactly(SaslException.class, () -> testMechanism(mechanism, "fred2@google.com", new String(password)));
  }

  void testMechanism(String mechanism, String user, String password) throws IOException {
    testMechanism(new ApacheBasicAuth("./src/test/resources/apache/.htpassword", "./src/test/resources/apache/.htgroups"), mechanism, user, password);
  }

  void testMechanism(IdentityLookup identityLookup, String mechanism, String user, String password) throws IOException {
    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);
    createServer(identityLookup, mechanism, PROTOCOL, SERVER_NAME, props);
    createClient(
        user,
        password,
        new String[]{mechanism},
        PROTOCOL,
        AUTHORIZATION_ID,
        SERVER_NAME,
        props
    );
    simpleValidation(user);
  }

  void simpleValidation(String user) throws IOException {
    assertNotNull(saslServer, "This should not be null");
    assertNotNull(saslClient, "This should not be null");
    runAuth();
    assertTrue(saslServer.isComplete());
    assertTrue(saslClient.isComplete());

    String qop = (String) saslClient.getNegotiatedProperty(Sasl.QOP);
    Assertions.assertEquals(saslServer.getAuthorizationID(), user);
    Assertions.assertTrue(qop.startsWith("auth"), "We should have an authorised SASL session");

    if (qop.equalsIgnoreCase("auth-conf")) {
      byte[] testBuffer = new byte[2048];
      for (int x = 0; x < testBuffer.length; x++) {
        testBuffer[x] = ((byte) (x & 0xff));
      }
      ClientWriter clientWriter = new ClientWriter(saslClient);
      writeInIncrements(clientWriter, testBuffer, 17);
      byte[] wrapped = writeInIncrements(clientWriter, testBuffer, 17);

      ServerWriter serverWriter = new ServerWriter(saslServer);
      byte[] unwrapped = writeInIncrements(serverWriter, wrapped, 43);
      Assertions.assertArrayEquals(testBuffer, unwrapped);
    }
  }

  private byte[] writeInIncrements(Writer writer, byte[] testBuffer, int inc) throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    int pos = 0;
    int len = inc;
    int end = len;

    while (pos < testBuffer.length) {
      byte[] t = writer.wrap(testBuffer, pos, len);
      byteArrayOutputStream.write(t);
      pos += inc;
      end += inc;
      if (end > testBuffer.length) {
        len = testBuffer.length - pos;
        inc = len;
      }
    }
    return byteArrayOutputStream.toByteArray();
  }

  private interface Writer {

    byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException;

    byte[] wrap(byte[] incoming, int offset, int len) throws SaslException;
  }

  private class ClientWriter implements Writer {

    private final SaslClient client;

    public ClientWriter(SaslClient client) {
      this.client = client;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
      return client.unwrap(incoming, offset, len);
    }

    @Override
    public byte[] wrap(byte[] incoming, int offset, int len) throws SaslException {
      return client.wrap(incoming, offset, len);
    }
  }

  private class ServerWriter implements Writer {

    private final SaslServer server;

    public ServerWriter(SaslServer server) {
      this.server = server;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
      return server.unwrap(incoming, offset, len);
    }

    @Override
    public byte[] wrap(byte[] incoming, int offset, int len) throws SaslException {
      return server.wrap(incoming, offset, len);
    }
  }
}
