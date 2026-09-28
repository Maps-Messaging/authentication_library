/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class ScramStringCoverageTest {

  @Test
  void escapesAndUnescapesSaslNames() throws Exception {
    String escaped = ScramString.escapeSaslName("a=b,c");

    assertEquals("a=3Db=2Cc", escaped);
    assertEquals("a=b,c", ScramString.unescapeSaslName(escaped));
  }

  @Test
  void rejectsMalformedSaslEscapes() {
    assertThrows(SaslException.class, () -> ScramString.unescapeSaslName("bad="));
    assertThrows(SaslException.class, () -> ScramString.unescapeSaslName("bad=2D"));
  }

  @Test
  void validatesNonceBoundariesAndCharacters() throws Exception {
    ScramString.requireNonce("abcXYZ123!~");
    ScramString.requireNonce("x".repeat(1024));

    assertThrows(SaslException.class, () -> ScramString.requireNonce(null));
    assertThrows(SaslException.class, () -> ScramString.requireNonce(""));
    assertThrows(SaslException.class, () -> ScramString.requireNonce("x".repeat(1025)));
    assertThrows(SaslException.class, () -> ScramString.requireNonce("has,comma"));
    assertThrows(SaslException.class, () -> ScramString.requireNonce("has space"));
    assertThrows(SaslException.class, () -> ScramString.requireNonce("bad" + (char) 0x7f));
  }
}
