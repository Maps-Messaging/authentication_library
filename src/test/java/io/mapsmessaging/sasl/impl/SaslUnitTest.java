package io.mapsmessaging.sasl.impl;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.sasl.impl.htpasswd.HashType;
import io.mapsmessaging.sasl.impl.htpasswd.HtPasswd;
import java.util.HashMap;
import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SaslUnitTest extends BaseSaslUnitTest {

  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "amqp";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth-conf";


  @ParameterizedTest
  @ValueSource(strings = {"DIGEST-MD5", "CRAM-MD5"})
  void simpleValidTest(String mechanism) throws SaslException {
    testMechanism(mechanism, "fred2@google.com", "This is a random password");
  }

  @ParameterizedTest
  @ValueSource(strings = {"DIGEST-MD5", "CRAM-MD5"})
  void simpleWrongPasswordTest(String mechanism) {
    Assertions.assertThrowsExactly(SaslException.class, () -> testMechanism(mechanism, "fred2@google.com", "This is a wrong password"));
  }

  void testMechanism(String mechanism, String user, String password) throws SaslException {
    Map<String, String> props = new HashMap<>();
    props.put(Sasl.QOP, QOP_LEVEL);
    createServer(new HtPasswd("./src/main/resources/.htpassword"), mechanism, PROTOCOL, SERVER_NAME, props);
    createClient(
        user,
        password,
        HashType.SHA1,
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
