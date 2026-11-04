# Operations, passwords and extension points

Use this with the [overview](overview.md), [configuration](../Config.md) and the provider-specific guides. This document describes the current development implementation.

## Password formats

`PasswordHandlerFactory` discovers password implementations using `ServiceLoader`. `getByClassName(...)` selects a prototype for creating a stored representation; `parse(char[])` selects a handler from an existing representation's prefix.

[PasswordExample.java](../examples/java/PasswordExample.java) creates a SHA-512-crypt value with a random printable salt, parses it and verifies both a correct and an incorrect password. It never prints the stored hash or supplied password.

Available implementations include bcrypt variants, PBKDF2 SHA variants, SHA/Unix formats, MD5 variants, plain values, multi-format handling and encrypted-password handling. Availability is for interoperability, not a recommendation to create new credentials in a legacy format. An unrecognized prefix falls back to the plain handler; validate accepted formats when importing a credential database.

Important integration details:

- Algorithm cost parameters differ: a bcrypt cost is not a PBKDF2 iteration count. Do not pass one generic work factor to every implementation.
- Preserve the entire encoded representation, including its prefix, salt and cost. Hashes are not interchangeable with plaintext SASL credentials.
- The implemented SCRAM server callback needs a recoverable password/compatible cipher, not an arbitrary one-way JAAS password hash. See [SASL](sasl.md) before choosing a shared credential store.
- Clear application-owned `char[]`/`byte[]` buffers when no longer needed, but do not claim complete secret zeroization: JCA/SDKs and immutable strings can retain copies. `PasswordBuffer.clear()` is not a guarantee that all underlying direct-memory bytes are overwritten.
- File-backed identity updates and policy management are separate operations. A successful login does not create a resource grant.

## Password verification findings

While executing the examples against this checkout, a newly generated bcrypt value failed `transformPassword` → stored-format parse → `matches` with the same password. The same failure was reproduced for PBKDF2-SHA256. The current constructors convert decoded binary digest bytes through UTF-8 character arrays; arbitrary digest bytes are not preserved by that conversion. These findings were observed in existing library code, not introduced or repaired by this documentation change.

Do not assume those handlers' presence in `ServiceLoader` means their create/store/reload/verify path is working. Reproduce your intended password format and reject deployment if correct credentials fail verification. The runnable examples use the existing SHA-512-crypt path, which was checked separately, to demonstrate integration without masking these defects. This is not advice to migrate a production credential database to a weaker or different policy.

There is also an implementation detail to review before choosing PBKDF2 parameters: `PBEKeySpec` expects its derived-key size in bits, while this implementation passes `getHashByteSize()` directly. Password functionality needs a separate code review/fix before relying on the affected formats.

## Stable identity and policy state

User/group mapping UUIDs are the link between identity backends and authorization grants. Keep mapping files stable across restarts and deployments. Rebuilding mappings with new UUIDs can leave old grants attached to identities no longer used by the application.

`MapFileStore` implements the mapping-store interface using local files. Provision parent directories, restrict access, and monitor its log messages: current mapping load/save methods log I/O failures instead of exposing a checked failure to every caller. Back up mapping data alongside ACL policy state and keystores. Test restoration as a set.

ACL persistence is encrypted using the key retained by its certificate manager. See [authorization](authorization.md) for the exact state path and startup/persistence error behaviour. OpenFGA persistence belongs to the external service; synchronize identity/group/resource lifecycle events as described there.

## Authentication monitoring

`AuthenticationMonitor` tracks failures, lockouts and successful recovery. [Config.md](../Config.md#authentication-monitoring) lists the defaults and units. The state is process-local, not a distributed account-locking service.

`IdentityAccessManager` installs the monitor in `IdentityLookupFactory`, which is a singleton. Treat initialization order and multiple managers in the same JVM deliberately; do not assume each independently created manager gets an isolated global monitor.

Carry the real connection `AuthContext` into the supported login path. Do not invent an IP address or reuse one user's context for all clients. Use the monitor through the documented authentication path rather than assuming a direct low-level password comparison performs lockout checks.

## Logging and failures

Library components use `io.mapsmessaging.logging.LoggerFactory` and `AuthLogMessages` enums. Keep the logging implementation/configuration compatible with the selected artifact. Authentication, authorization, store-loading and TLS initialization messages can be operationally significant even when the caller receives `null`, an empty result or a deny decision.

A standalone consumer also needs an application logging backend. The minimal examples POM does not choose one: without an SLF4J provider, its dependency stack reports that logging defaults to NOP. Reuse your application's compatible backend, or add exactly one SLF4J 2.x-compatible provider and its configuration when building a standalone application. Do not assume the logging facade alone will persist audit events.

The example programs write short demonstration results to standard output; they are not replacements for the application's security/audit logging. Do not record credentials, access tokens, private keys or complete configuration maps in diagnostics.

## Custom providers

The application can integrate an implementation by calling an interface directly or by registering it for factory discovery:

| Interface | Service descriptor |
| --- | --- |
| `IdentityLookup` | `META-INF/services/io.mapsmessaging.security.identity.IdentityLookup` |
| `AuthorizationProvider` | `META-INF/services/io.mapsmessaging.security.authorisation.AuthorizationProvider` |
| `PasswordHandler` | `META-INF/services/io.mapsmessaging.security.passwords.PasswordHandler` |
| `CertificateManager` | `META-INF/services/io.mapsmessaging.security.certificates.CertificateManager` |
| `Store` | `META-INF/services/io.mapsmessaging.security.storage.Store` |

Each descriptor lists implementation class names, one per line. Preserve existing descriptors when building a shaded JAR, normally by merging them through the packaging tool's service-resource transformer. Do not replace the library's existing entries with only your extension.

Implement the provider's configuration/create contract and capabilities explicitly. Interfaces have default no-ops or `UnsupportedOperationException` methods; implementing basic access checks does not automatically implement grant management, explanation or lifecycle synchronization. Document unsupported capabilities to callers.

`ResourceTraversalFactory` is application supplied and defines how resources map to parents. Keep tenant/type boundaries and traversal termination explicit. A custom identity backend must provide the principal/group/password behaviours needed by its selected JAAS/SASL integration, not just a display name.

## Shutdown and rotation

- Dispose each SASL client/server after success or failure.
- Close sockets/engines in the embedding application and log out JAAS sessions; discard their per-session Subjects.
- Shut down `CachingAuthorizationProvider` when its lifecycle ends. External policy changes and all lifecycle methods are not universally cache-invalidating; see [authorization](authorization.md).
- Treat password, TLS certificate, ACL encryption-key and peer-pin rotations as distinct workflows. Back up state before changing encryption keys; do not replace a persistent Ed25519 identity implicitly at runtime.
- Do not assume all cloud clients, certificate-manager instances or refresh tasks implement `AutoCloseable`. Check the implementation's lifecycle before hot-reloading or repeatedly constructing it.

## Troubleshooting

| Symptom | First checks |
| --- | --- |
| Factory returns `null` | Provider spelling, required configuration keys, service descriptors/runtime dependencies |
| JAAS login fails | Entry name, callback coverage including AuthContext, backend files/user and stored password format |
| SCRAM fails on final message | Ensure the client receives/verifies server-final; inspect mechanism policy, recoverable credential and iteration settings |
| Authenticated request is denied | Stable UUID/group mappings, exact tenant/type/name, permission mask/model and parent traversal |
| Unexpected access is allowed | Explicit provider selection; `Open` is permissive; check operation-level authorization calls |
| Permission changes appear stale | Cache lifetime, mutation path and external policy updates |
| TLS cannot recover a key | Key alias, store password versus private-key password, key-entry chain and selected manager algorithm |
| TLS trust/hostname failure | Trust anchors, certificate validity/SANs, peer host and endpoint-identification settings; do not disable verification to hide the failure |
| Persistent identity cannot load | Existing alias/type, passphrases and backed-up keystore; provisioning and runtime loading are separate |

Examples are a starting point for integration tests. Include wrong credentials, unknown users, explicit denial, cross-tenant resources, restart with persisted state, expired/untrusted certificates, hostname mismatch and malformed SASL messages in the application's own tests.
