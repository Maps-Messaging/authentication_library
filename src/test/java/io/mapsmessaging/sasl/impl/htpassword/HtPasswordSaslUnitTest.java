package io.mapsmessaging.sasl.impl.htpassword;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.auth.PasswordParser;
import io.mapsmessaging.auth.PasswordParserFactory;
import io.mapsmessaging.auth.parsers.Md5PasswordParser;
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
    testHashing("$apr1$po9cazbx$JG5SMaTSVYrtFlYQb821M.", "This is an md5 password");
  }

  @Test
  void checkBcryptHash(){
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
