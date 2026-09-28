/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.jaas;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.AuthContext;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import org.junit.jupiter.api.Test;

class BaseLoginModuleCoverageTest {

  @Test
  void successfulLoginCommitAbortAndLogoutLifecycle() throws Exception {
    TestModule module = new TestModule(true);
    Subject subject = new Subject();
    module.initialize(
        subject,
        callbacks -> populate(callbacks, "alice", "secret".toCharArray()),
        new LinkedHashMap<>(),
        Map.of("debug", "true"));

    assertTrue(module.login());
    assertTrue(module.commit());
    assertFalse(subject.getPrincipals().isEmpty());
    assertTrue(module.abort());
    assertTrue(subject.getPrincipals().isEmpty());
    assertTrue(module.logout());
  }

  @Test
  void failedValidationAndPreLoginCommitAbortPaths() {
    TestModule module = new TestModule(false);
    Subject subject = new Subject();
    module.initialize(
        subject,
        callbacks -> populate(callbacks, "alice", "secret".toCharArray()),
        new LinkedHashMap<>(),
        Map.of());

    assertFalse(module.commit());
    assertFalse(module.abort());
    assertThrows(LoginException.class, module::login);
  }

  @Test
  void missingCallbackHandlerAndCallbackFailuresAreReported() {
    TestModule noHandler = new TestModule(true);
    noHandler.initialize(new Subject(), null, new LinkedHashMap<>(), Map.of());
    assertThrows(LoginException.class, noHandler::login);

    TestModule ioFailure = new TestModule(true);
    ioFailure.initialize(
        new Subject(),
        callbacks -> { throw new IOException("boom"); },
        new LinkedHashMap<>(),
        Map.of());
    assertThrows(LoginException.class, ioFailure::login);

    TestModule unsupported = new TestModule(true);
    unsupported.initialize(
        new Subject(),
        callbacks -> { throw new UnsupportedCallbackException(callbacks[0]); },
        new LinkedHashMap<>(),
        Map.of());
    assertThrows(LoginException.class, unsupported::login);
  }

  @Test
  void nullPasswordIsTreatedAsEmptyPassword() throws Exception {
    TestModule module = new TestModule(true);
    module.initialize(
        new Subject(),
        callbacks -> populate(callbacks, "alice", null),
        new LinkedHashMap<>(),
        Map.of());

    assertTrue(module.login());
    assertEquals(0, module.lastPasswordLength);
  }

  private static void populate(Callback[] callbacks, String username, char[] password)
      throws UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback nameCallback) {
        nameCallback.setName(username);
      } else if (callback instanceof PasswordCallback passwordCallback) {
        if (password != null) {
          passwordCallback.setPassword(password);
        }
      } else if (callback instanceof AuthContextCallback authContextCallback) {
        authContextCallback.setAuthContext(new AuthContext("127.0.0.1", "test", "endpoint"));
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  private static final class TestModule extends BaseLoginModule {
    private final boolean valid;
    private int lastPasswordLength;

    private TestModule(boolean valid) {
      this.valid = valid;
    }

    @Override
    protected String getDomain() {
      return "test";
    }

    @Override
    protected boolean validate(String username, char[] password, AuthContext context) {
      lastPasswordLength = password.length;
      return valid;
    }
  }
}
