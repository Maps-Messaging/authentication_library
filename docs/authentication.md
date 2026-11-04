# Authentication

Authentication verifies credentials and produces a JAAS `Subject`. Authorization separately decides what a mapped `Identity` may do. Applications must enforce both at their connection/request boundary.

The complete [AuthenticationExample.java](../examples/java/AuthenticationExample.java) runs without an external service. It creates a temporary Apache password/group store, generates a SHA512-crypt hash for a clearly marked demo credential, supplies an in-memory JAAS `Configuration`, authenticates, logs out, verifies rejection of an incorrect password with a fresh subject and removes its temporary files. See [example build/run instructions](../examples/README.md).

## Objects and lifecycle

| Object | Role | Lifetime and important distinction |
| --- | --- | --- |
| `IdentityLookup` | Finds backend users, password handlers and groups | A configured backend instance; it is not a logged-in session |
| `IdentityEntry` | Backend representation of a user and its credential verifier | `getSubject()` returns a read-only backend subject; do not pass that subject as a mutable login target |
| `LoginContext` | Executes a configured JAAS module stack | Create one per login/session and call `login()` before using its subject |
| `Subject` | Holds authenticated principals and credentials | Use a fresh mutable subject per session; retire it after failed login or logout |
| `Principal` | A named fact such as username, group or authentication handler | A name principal alone is not an ACL identity UUID |
| `Identity` | UUID, username, attributes and mapped `Group` objects for authorization | Resolve from trusted identity mappings; do not accept user-supplied UUIDs as authenticated identity |
| `AuthContext` | Client IP, protocol and optional endpoint | Supply trustworthy connection context to the callback handler |

The usual JAAS path is:

1. Create a mutable `Subject`, callback handler and `LoginContext` for the intended JAAS application name.
2. Call `login()`. With `IdentityLoginModule`, the base module asks for username, password and `AuthContext`; the identity backend verifies the password/token through the entry's `PasswordHandler`.
3. On commit, `IdentityLoginModule` copies the backend subject's principals and credentials into the session subject. It adds `UserPrincipal` and `AuthHandlerPrincipal("Identity:" + lookup.getName())`. Ordinary backend entries also contribute named groups and `everyone`.
4. If stable UUID/group mappings are needed, use the configured `IdentityAccessManager` described below.
5. Perform explicit authorization checks for each protected operation.
6. Call `logout()` and discard the session subject and connection-local identity references.

Implementation details matter when managing subject reuse: `BaseLoginModule.abort()` clears all subject principals and credentials. Its `logout()` removes only its stored `userPrincipal`; it does not remove every principal or credential that a subclass added. The example therefore uses an exclusively owned session subject and clears that subject when the session ends. Do not share a mutable subject across independent logins or assume logout removes all identity/group state.

Sources: [BaseLoginModule](../src/main/java/io/mapsmessaging/security/jaas/BaseLoginModule.java), [IdentityLoginModule](../src/main/java/io/mapsmessaging/security/jaas/IdentityLoginModule.java), [IdentityEntry](../src/main/java/io/mapsmessaging/security/identity/IdentityEntry.java), [SubjectHelper](../src/main/java/io/mapsmessaging/security/SubjectHelper.java).

## JAAS configuration

An Apache file-backed entry can be configured in a JAAS file:

```text
LocalPasswordLogin {
  io.mapsmessaging.security.jaas.IdentityLoginModule required
    identityName="Apache-Basic-Auth"
    configDirectory="./examples/config/apache"
    debug="false";
};
```

The directory must exist and contain `.htpassword` and `.htgroups`. This snippet describes the layout; the runnable Java example generates its own fixtures and does not depend on files in that directory. With a JAAS file, select it at JVM startup using `-Djava.security.auth.login.config=/absolute/path/to/jaas.config` and construct `new LoginContext("LocalPasswordLogin", handler)`. The application's name must match the JAAS stanza. The example instead passes its `Configuration` directly to `LoginContext`, avoiding process-wide JAAS configuration changes.

`IdentityLoginModule` recognizes these options:

| Option | Meaning |
| --- | --- |
| `identityName` | Backend provider name, matched case-insensitively by `IdentityLookupFactory`; backend-specific options are passed to its `create` method |
| `siteWide` | Name previously registered with `IdentityLookupFactory.registerSiteIdentityLookup`; takes precedence over `identityName` |
| `debug` | String value `"true"` enables module debug logging; inherited from `BaseLoginModule` |

A `siteWide` entry requires registration before login. `IdentityAccessManager.setAsSystemIdentityLookup()` registers its configured backend under `system`; a JAAS entry can then use `siteWide="system"`. This reuses the lookup, not an authenticated subject. If neither option resolves a backend, there is no automatic anonymous fallback: validate the configuration before accepting connections. `IdentityLookupFactory.get(...)` returns `null` for an unknown provider; `getSiteWide(...)` returns `null` for an unregistered name.

Sources: [IdentityLookupFactory](../src/main/java/io/mapsmessaging/security/identity/IdentityLookupFactory.java), [IdentityAccessManager](../src/main/java/io/mapsmessaging/security/access/IdentityAccessManager.java). See also [configuration](../Config.md).

## Callbacks

| Module/path | Required callbacks | Supplied values |
| --- | --- | --- |
| `IdentityLoginModule` | `NameCallback`, `PasswordCallback`, `AuthContextCallback` | Username, password/token as `char[]`, non-null `AuthContext` |
| `Auth0JwtLoginModule` | Same three base callbacks | Username and JWT in the password callback; context should still be supplied |
| `AwsCognitoLoginModule` | Same three base callbacks | Username, password or access token, connection context |
| `SSLCertificateLoginModule` | `NameCallback`, `PrincipalCallback` | Application-mapped username and already authenticated TLS peer principal |
| `AnonymousLoginModule` | None in its login implementation | Adds the `anonymous` username principal without verifying a credential |

The handler should reject callbacks it does not support with `UnsupportedCallbackException`; do not silently ignore them. `IdentityLoginModule` dereferences `context.ipAddress()`, so failing to set `AuthContextCallback` is not a supported way to omit connection information. Construct `new AuthContext(null, protocol, endpoint)` if the IP is genuinely unavailable: it normalizes to `unknown`. Normalization also removes a leading slash, an IPv4 port and bracketed IPv6 port notation.

Pass secrets in character arrays and clear application-owned arrays after use. `PasswordCallback.setPassword` copies the array. The base module clears that callback after successful verification, but the implementation does not guarantee destruction of every internal copy or token string, especially on failure. The example's cleanup applies to its own buffers; it does not claim whole-process secret erasure.

Sources: [AuthContext](../src/main/java/io/mapsmessaging/security/access/AuthContext.java), [AuthContextCallback](../src/main/java/io/mapsmessaging/security/jaas/AuthContextCallback.java), [PrincipalCallback](../src/main/java/io/mapsmessaging/security/jaas/PrincipalCallback.java), [BaseLoginModule](../src/main/java/io/mapsmessaging/security/jaas/BaseLoginModule.java).

## Backend selection and local stores

The service registration currently contains:

| `identityName` | Implementation | Integration considerations |
| --- | --- | --- |
| `Apache-Basic-Auth` | `ApacheBasicAuth` | Local password/group files; useful for an offline integration example |
| `unix` | `UnixAuth` | Unix-format user/group/password sources; use deliberately supplied files and permissions |
| `ldap` | `LdapAuth` | Requires the configured directory connection and backend-specific settings |
| `cognito` | `CognitoAuth` | External AWS Cognito lookup; distinct from selecting the direct Cognito JAAS module |
| `auth0` | `Auth0Auth` | External Auth0 lookup; distinct from the direct JWT JAAS module |
| `Encrypted-Auth` | `EncryptedAuth` | Encrypted local storage and associated certificate/key configuration |

Preserve `META-INF/services` resources when packaging the library; both identity and password-handler discovery use `ServiceLoader`. Selecting a backend does not imply every management operation is supported. Consult `canManage()` and the concrete implementation before exposing account/group management.

For Apache, either provide `configDirectory` or explicit `passwordFile` and `groupFile` paths. Explicit `passwordFile` takes precedence. The filenames used by the directory mode are exactly `.htpassword` and `.htgroups`:

```text
# .htpassword format (replace HASH with a supported encoded hash; do not include this comment in the file):
demo-user:HASH

# .htgroups format (do not include this comment in the file):
operators: demo-user another-user
```

These readers do not implement shell-style comments in their input files. Named group members are separated by spaces. The Apache backend's hash parser recognizes the library's supported formats; this is not a claim that Apache HTTP Server supports every format accepted here. Unknown hash prefixes fall back to the plain password handler in `PasswordHandlerFactory.parse`, so validate the stored hash format rather than relying on rejection of malformed/unsupported formats.

The offline example uses `UnixSha512PasswordHasher.transformPassword` with a random 16-character hexadecimal salt and passes `hasher.getCost()`. The current Unix SHA implementation ignores that method's `cost` argument; this plain-salt path uses the underlying SHA512-crypt default rounds. This illustrates the actual API and deliberately avoids storing its known demo password as plaintext. It is not a recommendation for a workload-specific hashing cost. Existing stored hashes are parsed on read; the `passwordHandler` setting on `IdentityAccessManager` chooses the handler for account creation, rather than replacing every existing entry's verifier.

Current verification found that freshly generated bcrypt and PBKDF2 encoded values can fail the library's transform/parse/match round trip. The implementation converts decoded binary salt/digest material through UTF-8 character arrays, which can change those bytes. The runnable example therefore uses the verified ASCII SHA512-crypt path. This does not fix or certify the other hash implementations; do not assume that a recognized hash prefix proves a working credential-verification path.

File-backed lookup instances load files at construction. `findEntry()` itself does not trigger a file reload in `ApacheBasicAuth`. Do not assume an already configured site-wide instance automatically observes external file edits; define backend refresh/recreation and active-session refresh explicitly in the application.

Sources: [service registration](../src/main/resources/META-INF/services/io.mapsmessaging.security.identity.IdentityLookup), [ApacheBasicAuth](../src/main/java/io/mapsmessaging/security/identity/impl/apache/ApacheBasicAuth.java), [FileLoader](../src/main/java/io/mapsmessaging/security/identity/impl/base/FileLoader.java), [PasswordHandlerFactory](../src/main/java/io/mapsmessaging/security/passwords/PasswordHandlerFactory.java), [UnixSha512PasswordHasher](../src/main/java/io/mapsmessaging/security/passwords/hashes/sha/UnixSha512PasswordHasher.java).

## From Subject to a stable authorization Identity

`SubjectHelper` extracts the first matching username, authentication-handler, unique-ID or group-ID principal. A successful ordinary `IdentityLoginModule` login supplies the username and named groups, but does not itself assign the mapped authorization UUID. In particular, a named `everyone` group principal is not automatically an ACL grant.

For applications using `IdentityAccessManager`:

1. Initialize the manager with backend configuration, user/group `MapStore` implementations, a traversal factory, monitor configuration and the application's permissions.
2. Keep the user/group mapping stores durable. ACL grants refer to UUIDs, not usernames; recreating mappings with new UUIDs disconnects existing policy from users/groups.
3. Optionally call `setAsSystemIdentityLookup()` before constructing a JAAS entry using `siteWide="system"`.
4. After successful login, call `manager.updateSubject(subject)`. Check for a `null` result when the backend user no longer exists. This adds mapped `UniqueIdentifierPrincipal` and `GroupIdPrincipal` data; it does not authenticate a subject by itself.
5. Resolve the authorization object with `manager.getUserManagement().getUser(SubjectHelper.getUsername(subject))`. Check for a missing user before calling the authorization provider.

The returned `Identity` carries the UUID and groups used by ACL evaluation. Do not substitute `UUID.randomUUID()` on each login. The standalone authorization example uses fixed demonstration UUIDs only to keep its isolated fixture self-contained.

Identity/group objects are not automatic live subscriptions to backend changes. Re-resolve identities and retire/refresh session authorization state according to your account/group change policy. Also account for the [authorization cache lifecycle](authorization.md#authorization-cache) when group membership changes.

Sources: [UserManagement](../src/main/java/io/mapsmessaging/security/access/UserManagement.java), [GroupManagement](../src/main/java/io/mapsmessaging/security/access/GroupManagement.java), [Identity](../src/main/java/io/mapsmessaging/security/access/Identity.java), [SubjectHelper](../src/main/java/io/mapsmessaging/security/SubjectHelper.java).

## Authentication monitoring

`IdentityLoginModule` obtains the process-wide monitor from `IdentityLookupFactory`; if none is set, it installs a monitor with `AuthenticationMonitorConfig` defaults. `IdentityAccessManager` installs a monitor using the configuration supplied to its constructor. Account for this shared factory state when configuring several managers in one JVM.

The module checks lockout using username and normalized client IP before password validation, records success on a match and records failure otherwise. Its monitoring path also records a failure when the password handler throws `IOException` or `GeneralSecurityException`. Do not infer that the independent JWT or certificate modules use this same monitored validation path.

Current configuration defaults are five failures, initial lock 30 s, maximum lock 900 s, failure decay 900 s, soft delay enabled, 200 ms per failure and maximum soft delay 2000 ms. These are implementation defaults, not a complete endpoint abuse policy. Derive the IP from the actual connection or a trusted proxy boundary.

Sources: [AuthenticationMonitorConfig](../src/main/java/io/mapsmessaging/security/access/monitor/AuthenticationMonitorConfig.java), [AuthenticationMonitor](../src/main/java/io/mapsmessaging/security/access/monitor/AuthenticationMonitor.java).

## Other JAAS modules

| Module | Options read by the implementation | Behavior |
| --- | --- | --- |
| `Auth0JwtLoginModule` | `auth0Domain`, `audience`, inherited `debug` | Validates a JWT supplied as the password, then compares the username to its subject after removing a terminal `@clients` suffix |
| `AwsCognitoLoginModule` | `region`, `userPoolId`, `accessKeyId`, `secretAccessKey`, `appClientId`, `appClientSecret`, inherited `debug` | Uses an AWS Cognito client; supports password or access-token paths and adds returned named groups on commit |
| `SSLCertificateLoginModule` | Inherited `debug` | Accepts the supplied principal and username; it does not perform a TLS handshake or certificate-chain verification |
| `AnonymousLoginModule` | Inherited base options | Accepts an anonymous login without credentials; its constructor explicitly logs that it should not be used in production |

The certificate module belongs after successful transport-level peer authentication. Supplying an arbitrary `Principal` to its callback is not certificate verification. Configure TLS trust, peer-certificate requirements and username mapping at the transport boundary; see the [certificate/SSL guide](certificates-and-tls.md).

Sources: [Auth0JwtLoginModule](../src/main/java/io/mapsmessaging/security/jaas/Auth0JwtLoginModule.java), [AwsCognitoLoginModule](../src/main/java/io/mapsmessaging/security/jaas/AwsCognitoLoginModule.java), [SSLCertificateLoginModule](../src/main/java/io/mapsmessaging/security/jaas/SSLCertificateLoginModule.java), [AnonymousLoginModule](../src/main/java/io/mapsmessaging/security/jaas/AnonymousLoginModule.java).

## Failures to handle at the application boundary

- A `LoginException` means the connection/request has not completed authentication. Do not continue with an old identity or partially populated subject.
- Check backend/provider resolution before serving traffic; unknown providers and missing site-wide names can return `null`.
- Supply every callback required by the selected module, including non-null context for `IdentityLoginModule`.
- Distinguish credential rejection from configuration/service errors in internal diagnostics without exposing passwords, tokens or full subject credentials.
- After authentication, perform [authorization](authorization.md); neither a username nor a group-name principal alone grants resource access.

The local example demonstrates one required JAAS module. Multi-module stacks must also account for each module's commit/abort/logout behavior; this guide does not claim subject cleanup isolation between modules.
