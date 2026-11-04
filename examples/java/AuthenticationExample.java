/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.AuthContext;
import io.mapsmessaging.security.jaas.AuthContextCallback;
import io.mapsmessaging.security.jaas.IdentityLoginModule;
import io.mapsmessaging.security.passwords.hashes.sha.UnixSha512PasswordHasher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/** Local demonstration only: generates a temporary Apache password/group store and logs in through JAAS. */
public final class AuthenticationExample {
  private static final String APPLICATION = "LocalAuthenticationExample";
  private static final String USERNAME = "demo-user";

  private AuthenticationExample() {}

  public static void main(String[] arguments) throws IOException, LoginException {
    Path directory = Files.createTempDirectory("authentication-example-");
    // Known demo credential, never a production secret.
    char[] password = "demo-only-password".toCharArray();
    try {
      writeDemoStore(directory, password);
      Configuration configuration = new LocalConfiguration(directory);
      AuthContext context = new AuthContext("127.0.0.1", "example", "local");
      try (CredentialsHandler handler = new CredentialsHandler(USERNAME, password, context)) {
        Subject subject = new Subject();
        LoginContext login = new LoginContext(APPLICATION, subject, handler, configuration);
        boolean loggedIn = false;
        try {
          login.login();
          loggedIn = true;
          System.out.println("Authenticated: " + SubjectHelper.getUsername(subject));
          System.out.println("Authentication domain: " + SubjectHelper.getAuthDomain(subject));
          System.out.println("Principals: " + subject.getPrincipals());
          // A JAAS Subject does not automatically contain the stable UUID required by ACL authorization.
          System.out.println("Mapped identity UUID: " + SubjectHelper.getUniqueId(subject));
        } finally {
          try {
            if (loggedIn) {
              login.logout();
            }
          } finally {
            // IdentityLoginModule adds principals beyond the base module's logout removal.
            // This Subject belongs exclusively to this completed example session.
            clearSubject(subject);
          }
        }
      }
      expectRejectedLogin(configuration, context);
    } finally {
      Arrays.fill(password, '\0');
      Files.deleteIfExists(directory.resolve(".htpassword"));
      Files.deleteIfExists(directory.resolve(".htgroups"));
      Files.deleteIfExists(directory);
    }
  }

  private static void expectRejectedLogin(Configuration configuration, AuthContext context) throws LoginException {
    char[] wrongPassword = "deliberately-wrong-demo-password".toCharArray();
    Subject subject = new Subject();
    try (CredentialsHandler handler = new CredentialsHandler(USERNAME, wrongPassword, context)) {
      LoginContext login = new LoginContext(APPLICATION, subject, handler, configuration);
      boolean loggedIn = false;
      try {
        try {
          login.login();
          loggedIn = true;
        } catch (LoginException expected) {
          // Do not count a missing backend or configuration error as proof of credential rejection.
          if (!"Username or password is invalid".equals(expected.getMessage())) {
            throw expected;
          }
          System.out.println("Incorrect password rejected");
          return;
        }
        throw new IllegalStateException("Incorrect password unexpectedly authenticated");
      } finally {
        if (loggedIn) {
          login.logout();
        }
      }
    } finally {
      Arrays.fill(wrongPassword, '\0');
      clearSubject(subject);
    }
  }

  private static void clearSubject(Subject subject) {
    subject.getPrincipals().clear();
    subject.getPublicCredentials().clear();
    subject.getPrivateCredentials().clear();
  }

  private static void writeDemoStore(Path directory, char[] password) throws IOException {
    byte[] randomSalt = new byte[8];
    new SecureRandom().nextBytes(randomSalt);
    byte[] salt = HexFormat.of().formatHex(randomSalt).getBytes(StandardCharsets.US_ASCII);
    UnixSha512PasswordHasher hasher = new UnixSha512PasswordHasher();
    char[] hash = hasher.transformPassword(password, salt, hasher.getCost());
    try {
      // The Apache backend accepts the library's supported hash formats, including SHA512-crypt.
      Files.writeString(directory.resolve(".htpassword"), USERNAME + ":" + new String(hash) + "\n", StandardCharsets.UTF_8);
      Files.writeString(directory.resolve(".htgroups"), "operators: " + USERNAME + "\n", StandardCharsets.UTF_8);
    } finally {
      Arrays.fill(hash, '\0');
      Arrays.fill(salt, (byte) 0);
      Arrays.fill(randomSalt, (byte) 0);
    }
  }

  private static final class LocalConfiguration extends Configuration {
    private final Map<String, String> options;

    private LocalConfiguration(Path directory) {
      options = Map.of("identityName", "Apache-Basic-Auth", "configDirectory", directory.toString(), "debug", "false");
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
      if (!APPLICATION.equals(name)) {
        return null;
      }
      return new AppConfigurationEntry[] {
        new AppConfigurationEntry(IdentityLoginModule.class.getName(), AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)
      };
    }
  }

  private static final class CredentialsHandler implements CallbackHandler, AutoCloseable {
    private final String username;
    private final char[] password;
    private final AuthContext context;

    private CredentialsHandler(String username, char[] password, AuthContext context) {
      this.username = username;
      this.password = password.clone();
      this.context = context;
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback nameCallback) {
          nameCallback.setName(username);
        } else if (callback instanceof PasswordCallback passwordCallback) {
          passwordCallback.setPassword(password);
        } else if (callback instanceof AuthContextCallback authContextCallback) {
          authContextCallback.setAuthContext(context);
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
    }

    @Override
    public void close() {
      Arrays.fill(password, '\0');
    }
  }
}
