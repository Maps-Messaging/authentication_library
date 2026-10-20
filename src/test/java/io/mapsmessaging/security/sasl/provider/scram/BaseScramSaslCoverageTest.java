/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class BaseScramSaslCoverageTest {

  @Test
  void coversEmptyResponseCompleteAndDisposeGuards() throws Exception {
    ExposedScram sasl = new ExposedScram();
    sasl.setState(new StubState(false, null));

    assertFalse(sasl.isComplete());
    assertNull(sasl.evaluateChallenge(new byte[0]));

    sasl.setState(new StubState(true, null));
    assertTrue(sasl.isComplete());
    assertThrows(SaslException.class, () -> sasl.evaluateChallenge(new byte[0]));

    sasl.dispose();
    assertFalse(sasl.isComplete());
    sasl.dispose();
    assertThrows(SaslException.class, () -> sasl.evaluateChallenge(new byte[0]));
  }

  @Test
  void rejectsOversizedAndWrapsInvalidExchange() throws Exception {
    ExposedScram sasl = new ExposedScram();
    sasl.setState(new StubState(false, new ChallengeResponse("r=abc")));

    assertArrayEquals(
        "r=abc".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        sasl.evaluateChallenge(new byte[0]));

    assertThrows(
        SaslException.class,
        () -> sasl.evaluateChallenge(new byte[16 * 1024 + 1]));

    ExposedScram failing = new ExposedScram();
    failing.setState(new StubState(false, null) {
      @Override
      public void handleResponse(ChallengeResponse response, SessionContext context)
          throws IOException {
        throw new IOException("boom");
      }
    });

    SaslException failure =
        assertThrows(SaslException.class, () -> failing.evaluateChallenge("r=abc".getBytes()));
    assertInstanceOf(IOException.class, failure.getCause());

    assertThrows(IllegalStateException.class, () -> sasl.wrap(new byte[1], 0, 1));
    assertThrows(IllegalStateException.class, () -> sasl.unwrap(new byte[1], 0, 1));
    assertThrows(IllegalStateException.class, sasl::callRequireComplete);
  }

  private static final class ExposedScram extends BaseScramSasl {
    void setState(State state) {
      context.setState(state);
    }

    void callRequireComplete() {
      requireComplete();
    }
  }

  private static class StubState extends State {
    private final boolean complete;
    private final ChallengeResponse response;

    StubState(boolean complete, ChallengeResponse response) {
      super(null, "mqtt", "server", java.util.Map.of(), callbacks -> {});
      this.complete = complete;
      this.response = response;
    }

    @Override public boolean isComplete() { return complete; }
    @Override public boolean hasInitialResponse() { return true; }
    @Override public ChallengeResponse produceChallenge(SessionContext context) { return response; }
    @Override
    public void handleResponse(ChallengeResponse response, SessionContext context)
        throws IOException {}
  }
}
