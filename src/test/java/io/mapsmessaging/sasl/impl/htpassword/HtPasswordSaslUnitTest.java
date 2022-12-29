package io.mapsmessaging.sasl.impl.htpassword;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import io.mapsmessaging.auth.PasswordParser;
import io.mapsmessaging.auth.PasswordParserFactory;
import io.mapsmessaging.auth.parsers.BCryptPasswordParser;
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
    String encoded = "$apr1$po9cazbx$JG5SMaTSVYrtFlYQb821M.";
    PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(encoded);
    Assertions.assertArrayEquals(encoded.toCharArray(), HashType.MD5.getPasswordHash().hash("This is an md5 password", new String(passwordParser.getSalt()) ));
  }

  @Test
  void checkBcryptHash(){
    String encoded = "$2y$10$usnulDZ/2qo7.8h9k1tgZO2trerPMjuIx8PtClu8Uk.28amTowoFq";
    BCryptPasswordParser passwordParser = (BCryptPasswordParser) PasswordParserFactory.getInstance().parse(encoded);
    byte[] hash = BCrypt.with(Version.VERSION_2Y).hash(10, passwordParser.getRawSalt(), "This Is A Password".getBytes());
    Assertions.assertArrayEquals(encoded.getBytes(), hash);
  }

  @Test
  void listProviders(){
    Provider[] providers = Security.getProviders();
    for(Provider provider:providers){
      if(provider.getName().toLowerCase().contains("sasl")){
        System.err.println(provider.getName());
        for(Service service:provider.getServices()){
          System.err.println("\t"+service.getType()+" "+service.getAlgorithm());
        }
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"DIGEST-MD5", "CRAM-MD5"})
  void simpleDigestNonSaltValidTest(String mechanism) throws SaslException {
    testMechanism(mechanism, "fred2@google.com", "This is a random password");
  }

  @ParameterizedTest
  @ValueSource(strings = {"SCRAM"})
  void simpleScramValidTest(String mechanism) throws SaslException {
    testMechanism(mechanism, "fred3@google.com", "This is a random password");
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
    System.err.println(saslClient.getClass().getName()+" <> "+saslServer.getClass().getName());
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
