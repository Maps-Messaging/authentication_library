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
import org.junit.jupiter.api.Assertions;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SaslTester extends BaseSasl {

  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "anyProtocol";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth";

  public void testMechanism(
      IdentityLookup identityLookup, String mechanism, String user, char[] password)
      throws IOException {
    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);
    createServer(identityLookup, mechanism, PROTOCOL, SERVER_NAME, props);
    createClient(user, password, new String[] {mechanism}, PROTOCOL, AUTHORIZATION_ID, SERVER_NAME, props);
    simpleValidation(user, mechanism);
  }

  void simpleValidation(String user, String mechanism) throws IOException {
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
    Assertions.assertTrue(mechanism.startsWith(saslServer.getMechanismName()));
    Assertions.assertTrue(mechanism.startsWith(saslClient.getMechanismName()));
    saslServer.dispose();
    saslClient.dispose();
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

  private static class ClientWriter implements Writer {

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

  private static class ServerWriter implements Writer {

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
