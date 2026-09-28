/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.msgs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class ChallengeResponseCoverageTest {

  @Test
  void parsesGs2HeaderAndAttributesInOrder() throws Exception {
    ChallengeResponse response =
        new ChallengeResponse("n,a=proxy,n=alice,r=nonce");

    assertEquals("n,a=proxy,", response.getGs2Header());
    assertEquals("alice", response.get(ChallengeResponse.USERNAME));
    assertEquals("nonce", response.get(ChallengeResponse.NONCE));
    assertEquals(List.of("n", "r"), response.keys());
    assertEquals("n=alice,r=nonce", response.getBareMessage());
    assertEquals("n,a=proxy,n=alice,r=nonce", response.toString());
    assertFalse(response.isEmpty());

    assertEquals("nonce", response.remove(ChallengeResponse.NONCE));
    assertFalse(response.contains(ChallengeResponse.NONCE));
  }

  @Test
  void supportsProgrammaticConstructionAndProtectsValuesView() {
    ChallengeResponse response = new ChallengeResponse();
    response.setGs2Header("y,,");
    response.put("n", "alice");
    response.put("r", "nonce");

    assertEquals("y,,n=alice,r=nonce", response.toString());
    assertThrows(
        UnsupportedOperationException.class,
        () -> response.values().put("x", "value"));
    assertThrows(
        IllegalArgumentException.class,
        () -> response.put("n", "duplicate"));
    assertThrows(
        IllegalArgumentException.class,
        () -> response.put("xx", "invalid"));
    assertThrows(
        IllegalArgumentException.class,
        () -> response.put("x", null));
    assertThrows(
        IllegalArgumentException.class,
        () -> response.setGs2Header("invalid"));
  }

  @Test
  void rejectsMalformedMessages() {
    assertThrows(IOException.class, () -> new ChallengeResponse((String) null));
    assertThrows(IOException.class, () -> new ChallengeResponse("p=unsupported"));
    assertThrows(IOException.class, () -> new ChallengeResponse("n,a=user"));
    assertThrows(IOException.class, () -> new ChallengeResponse("n,x"));
    assertThrows(IOException.class, () -> new ChallengeResponse("n=alice,,r=nonce"));
    assertThrows(IOException.class, () -> new ChallengeResponse("name=value"));
    assertThrows(IOException.class, () -> new ChallengeResponse("m=value"));
    assertThrows(IOException.class, () -> new ChallengeResponse("n=alice,n=bob"));
    assertThrows(
        IOException.class,
        () -> new ChallengeResponse(new byte[]{(byte) 0xc3, 0x28}));
  }

  @Test
  void parsesUtf8Bytes() throws Exception {
    ChallengeResponse response =
        new ChallengeResponse("n=alice,r=nonce".getBytes(StandardCharsets.UTF_8));

    assertTrue(response.contains("n"));
    assertEquals("nonce", response.get("r"));
  }
}
