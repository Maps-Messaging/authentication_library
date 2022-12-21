package io.mapsmessaging.sasl.impl.htpassword;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.sasl.impl.BaseSaslUnitTest;
import io.mapsmessaging.sasl.impl.htpasswd.HashType;
import io.mapsmessaging.sasl.impl.htpasswd.HtPasswd;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HtPasswordSaslUnitTest extends BaseSaslUnitTest {

  private static final String SERVER_NAME = "myServer";
  private static final String PROTOCOL = "amqp";
  private static final String AUTHORIZATION_ID = null;
  private static final String QOP_LEVEL = "auth";

  @Test
  void checkMd5Hash(){
    Assertions.assertArrayEquals("$apr1$po9cazbx$JG5SMaTSVYrtFlYQb821M.".toCharArray(), HashType.MD5.getPasswordHash().hash("This is an md5 password","po9cazbx" ));
  }

  void checkBcryptHash(){
    Assertions.assertArrayEquals("BzVXd/hbkglo7bRLVZwYEu/45Uy24FsoZBHEaJqi690AJzIOV/Q5u".toCharArray(), HashType.BCRYPT.getPasswordHash().hash("This is an bcrypt password","$2y$10$BzVXd/hbkglo7bRLVZwYEu/45Uy24FsoZBHEaJqi690AJzIOV/Q5u" ));
  }

  @Test
  void listProviders(){
    Provider[] providers = Security.getProviders();
    for(Provider provider:providers){
      System.err.println(provider.getName());
      for(Service service:provider.getServices()){
        System.err.println("\t"+service.getType()+" "+service.getAlgorithm());
      }
    }
  }

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
    createServer(new HtPasswd("./src/test/resources/.htpassword"), mechanism, PROTOCOL, SERVER_NAME, props);
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
