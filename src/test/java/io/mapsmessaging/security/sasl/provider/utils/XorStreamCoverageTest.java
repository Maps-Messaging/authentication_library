/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class XorStreamCoverageTest {

  @Test
  void xorUsesOffsetAndWrapsKeyAcrossCalls() {
    XorStream stream = new XorStream(new byte[]{1, 2, 3});

    assertArrayEquals(
        new byte[]{11, 9, 15, 12},
        stream.xorBuffer(new byte[]{99, 10, 11, 12, 13, 98}, 1, 4));

    assertArrayEquals(
        new byte[]{22, 22, 23},
        stream.xorBuffer(new byte[]{20, 21, 22}, 0, 3));
  }
}
