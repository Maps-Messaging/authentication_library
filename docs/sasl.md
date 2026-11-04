# SASL in a standalone application

The library supplies Java SASL client and server implementations for `SCRAM-SHA-256` and `PLAIN`.
Your application supplies credential callbacks, transports the exchanged bytes, and applies the resulting identity to its own session.
A MapsMessaging server, JAAS login configuration, identity-store configuration file, and authorization service are not required for the example below.

## Run a complete SCRAM exchange

[examples/java/SaslExample.java](../examples/java/SaslExample.java) is a complete Java class with both callback handlers and an in-process exchange.
It uses fixed demonstration credentials for `alice`; replace those with independent client credential acquisition and server credential lookup.
Do not use the demonstration password as an application credential.

Build the checkout and examples using the [shared setup commands](../examples/README.md#build-against-this-checkout), then run from the repository root:

```sh
export CLASSPATH='examples/target/classes:examples/target/dependency/*'
java -cp "$CLASSPATH" SaslExample
```

This POSIX example uses `:` classpath separators; [the examples README](../examples/README.md) includes the Windows PowerShell equivalent with `;`.
The example needs the library and its runtime dependencies, including the logging library, Bouncy Castle and the Ongres stringprep libraries; it needs no external files or services.
Expected output:

```text
Authenticated and authorized: alice; QOP=auth
```

`MapsSecurityProvider.register()` installs the `MapsSasl` provider at the beginning of the JVM provider list if it is not already registered.
Loading this provider also registers Bouncy Castle. Register once during application initialization, before calling `Sasl.createSaslClient` or `Sasl.createSaslServer`.
Registration affects the JVM's provider list; it is not scoped to an individual connection.
Applications that deliberately avoid global SASL provider registration can instantiate
`io.mapsmessaging.security.sasl.provider.MapsSaslClientFactory` and `MapsSaslServerFactory` directly through the standard factory interfaces.

The example requests only `SCRAM-SHA-256`, `Sasl.QOP = "auth"`, and `Sasl.POLICY_NOPLAINTEXT = "true"`.
Check for a `null` result from either SASL creation method: this means no available provider satisfied the mechanism and policy selection.

## Callbacks and credential storage

| Callback | Client responsibility | Server responsibility |
| --- | --- | --- |
| `NameCallback` | Set the authentication username with `setName`. | Read `getDefaultName()`, look up that identity, and set its recognized name. |
| `PasswordCallback` | Set the user's password as a `char[]`. | Set the stored credential belonging to the requested authentication identity. |
| `AuthorizeCallback` | Not requested by these clients. | Explicitly accept or reject the requested authorization identity; set the accepted ID if needed. |

Both mechanisms invoke the server's name/password callbacks before invoking `AuthorizeCallback`.
Reject unsupported callback types with `UnsupportedCallbackException`; do not silently ignore them.
The example resolves the requested name before supplying its credential, and allows only an authenticated user acting as the same user.
A nonempty authorization ID passed to `createSaslClient` requests that identity; omitting it lets the server use the authentication identity.
Accepting a password does not grant permission to impersonate another account.

For SCRAM, the current server implementation parses the callback credential with `PasswordHandlerFactory` and accepts
`PlainPasswordHasher` or `PasswordCipher` implementations. It recovers the password and derives SCRAM material for the exchange.
The callback may therefore supply the recoverable password directly, as the example does, or a supported encrypted password representation with its decryption setup.
A bcrypt, Argon2, PBKDF2, or other one-way password hash cannot be substituted for the password in this SCRAM implementation.
There is no stored SCRAM-verifier callback in the current implementation.

PLAIN can validate supported stored password hashes through `PasswordHandlerFactory` and can decrypt supported `PasswordCipher` representations.
The client still supplies its original password. Keep server credential representations distinct from client passwords.

The SASL implementations clear their password callback and dispose internal state when `dispose()` is called.
The example additionally clears the credential arrays it owns, and attempts to dispose both peers even if authentication fails.
Replace the local callbacks with your credential store integration; do not log passwords, callback credential values, or raw PLAIN responses.

## Transport integration and completion

For SCRAM, transfer these four messages using your protocol's SASL framing:

1. The client calls `evaluateChallenge(new byte[0])` and sends the client-first bytes.
2. The server calls `evaluateResponse(clientFirst)` and sends the server-first bytes.
3. The client calls `evaluateChallenge(serverFirst)` and sends the client-final proof.
4. The server calls `evaluateResponse(clientFinal)` and sends the server-final verifier. The client calls `evaluateChallenge(serverFinal)` to validate it.

The server reports completion after producing its final verifier. The client reports completion only after validating that verifier.
Do not stop the exchange when only the server is complete, discard the server-final bytes, or interpret a `null` client final response as a failure:
it means there are no further client bytes to send after successful verifier validation.
Do not invoke another evaluation after completion.

A network protocol may carry the verifier in its authentication success frame rather than a separate challenge frame.
In that case, feed the success frame's SASL data into `evaluateChallenge` before treating the client session as authenticated.
Preserve message boundaries and bytes; add only the framing required by the enclosing protocol.
On an evaluation exception, fail the session and dispose its SASL object. Create fresh objects for a new attempt.

Read `SaslServer.getAuthorizationID()` only after successful completion. This is the identity accepted by the authorization callback.
The SASL provider does not create a JAAS `Subject`, attach library principals, or perform application resource authorization.
Associate the accepted ID with your application's session or resolve it through your chosen identity backend, then apply your application's authorization checks.

## Policies and implementation limits

Both factories apply the following properties when selecting mechanisms:

| Property | Current behavior |
| --- | --- |
| `Sasl.QOP` | Accepts an absent property or a comma-separated list containing `auth`; rejects a list without `auth`. |
| `Sasl.POLICY_NOPLAINTEXT` | When true, excludes PLAIN; SCRAM remains eligible. |
| `Sasl.POLICY_NOACTIVE` | When true, excludes PLAIN; SCRAM remains eligible. |
| `Sasl.POLICY_NODICTIONARY` | When true, excludes both mechanisms. |
| `Sasl.POLICY_FORWARD_SECRECY` | When true, excludes both mechanisms. |
| `Sasl.POLICY_PASS_CREDENTIALS` | When true, excludes both mechanisms. |

Policy values are interpreted using `Boolean.parseBoolean(String.valueOf(value))`; use the strings `"true"` and `"false"`.
These are mechanism-selection policies, not transport configuration. In particular, disabling `POLICY_NOPLAINTEXT` does not establish or verify TLS.

PLAIN sends the password in its SASL response. Offer or select it only after establishing a TLS connection and verifying the peer according to your application's TLS policy.
Enforce that restriction in your application before constructing or advertising PLAIN; the factories do not receive a TLS connection and cannot enforce it.
Once TLS is established, properties allowing PLAIN can be constructed as follows:

```java
Map<String, String> plainOverTlsProperties = Map.of(Sasl.QOP, "auth", Sasl.POLICY_NOPLAINTEXT, "false");
```

Use these properties only in the application path that has already completed TLS validation, and use `"PLAIN"` as the requested mechanism.
Do not fall back automatically from SCRAM to PLAIN on an unprotected connection.

Both implementations negotiate authentication only (`auth`). They do not implement `auth-int` or `auth-conf`, and `wrap`/`unwrap` throw `IllegalStateException`.
Continue protecting application traffic with TLS; SASL does not supply encryption or message integrity for it.
Only `SCRAM-SHA-256` is registered: there is no `SCRAM-SHA-256-PLUS`, TLS channel binding, or registered SCRAM SHA-1/SHA-512 variant.
The SCRAM client sends a GS2 `n` header; the server checks the returned GS2 header bytes, which is not TLS channel binding.

SCRAM has two implementation-specific properties, in addition to standard SASL policy properties:

| Property | Applied by | Default and validation |
| --- | --- | --- |
| `io.mapsmessaging.security.sasl.scram.iterations` | Server | Default `10000`; accepts integer values from `4096` through `1000000`. |
| `io.mapsmessaging.security.sasl.scram.maxIterations` | Client | Default `1000000`; rejects server iteration counts below `4096` or above the configured maximum. |

Both values are parsed as integers from `String.valueOf(value)`.
Choose an iteration policy consistent with your client CPU budget and server requirements; a client maximum lower than the server's configured value rejects the exchange.
