/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

class CryptoHelperCoverageTest {

  @Test
  void resolvesSupportedDigestAndMacAlgorithms() throws Exception {
    assertEquals("SHA-256", CryptoHelper.findDigest("SHA-256").getAlgorithm());
    assertNotNull(CryptoHelper.findMac("SHA-256"));
    assertNull(CryptoHelper.findMac("SHA-1"));
  }

  @Test
  void retriesDigestWithoutDashAndPropagatesUnknownAlgorithm() throws Exception {
    assertEquals("SHA-256", CryptoHelper.findDigest("SHA256").getAlgorithm());
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> CryptoHelper.findDigest("definitely-not-a-real-digest"));
  }
}
