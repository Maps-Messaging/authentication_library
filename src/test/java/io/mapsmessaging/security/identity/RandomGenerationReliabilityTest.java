/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import org.junit.jupiter.api.Test;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;

class RandomGenerationReliabilityTest {

  @Test
  void passwordGeneratorReturnsRequestedLengths() {
    String salt = PasswordGenerator.generateSalt(32);
    byte[] bytes = PasswordGenerator.generateSaltBytes(48);

    assertEquals(32, salt.length());
    assertEquals(48, bytes.length);
    assertTrue(salt.chars().allMatch(c ->
        Character.isLetterOrDigit(c)));
  }

  @Test
  void scramRandomGenerationReturnsRequestedEntropyLength() {
    byte[] bytes = CryptoHelper.generateRandomBytes(24);
    String nonce = CryptoHelper.generateNonce(24);

    assertEquals(24, bytes.length);
    assertEquals(24, Base64.getDecoder().decode(nonce).length);
  }
}
