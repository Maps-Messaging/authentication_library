# Configuration reference

This reference describes the current development source, not every historical release. See the [overview](docs/overview.md) and [complete examples](examples/README.md) for integration order.

## Loading configuration

There is no single application configuration file automatically loaded by this library. JAAS reads its configured entries; identity/policy/certificate factories receive maps or `ConfigurationProperties` supplied by the embedding application.

The JSON files under [examples/config](examples/config) are templates. Load the selected object with your application's JSON/YAML loader, replace placeholder secrets and pass it to the corresponding factory. Preserve nested objects: the ACL `certificateStore` and TLS `keyStore`/`trustStore` values are read as `ConfigurationProperties`, not flattened property names.

For programmatic configuration, construct nested values explicitly as shown in [TlsExample.java](examples/java/TlsExample.java). Do not assume plain Java `Properties`, an arbitrary YAML object, and `ConfigurationProperties` are interchangeable.

Provider names below are the values returned by the implementations; factory lookup is case-insensitive. Check for `null` when a factory cannot resolve an implementation.

## Identity providers

Pass an identity name and its configuration map to `IdentityLookupFactory.getInstance().get(name, config)`, or supply `identityName` and the same options to `IdentityLoginModule` through JAAS.

| Provider name | Properties | Notes |
| --- | --- | --- |
| `Apache-Basic-Auth` | `passwordFile`, optional `groupFile`; alternatively `configDirectory` | Directory mode expects `.htpassword` and `.htgroups`. Explicit file paths take precedence. See [apache.json](examples/config/apache.json). |
| `unix` | `passwordFile`, `groupFile`, `passwd`; alternatively `configDirectory` | Uses Unix-format password/group/account files; this does not invoke PAM. Check the chosen files and OS permissions. |
| `Encrypted-Auth` | Apache-style paths plus nested `certificateStore` | Directory mode uses `.htpassword-enc` and `.htgroups`. Certificate config also needs `alias`, literal keys `privateKey.name` and `privateKey.passphrase`. |
| `ldap` | `java.naming.provider.url`, `java.naming.security.principal`, `java.naming.security.credentials`, `passwordKeyName`, `searchBase`, `groupSearchBase` | JNDI configuration keys are passed through. Initial context factory defaults to `com.sun.jndi.ldap.LdapCtxFactory`; security authentication defaults to `simple`. This backend reads directory password attributes; do not assume a per-user LDAP bind flow. |
| `cognito` | `userPoolId`, `appClientId`, `appClientSecret`, `region`, `accessKeyId`, `secretAccessKey`, optional `cacheTime` | Requires access to the configured AWS Cognito user pool and suitable API permissions. |
| `auth0` | `domain`, `clientId`, `clientSecret`, optional `cacheTime` | Obtains a Management API token using the client credentials. An `authToken` property is not read by the current `Auth0Auth` constructor. |

For cloud backends, verify supported flows, SDK errors and cache semantics against your selected release; a configured backend does not imply the external service is reachable. Do not copy service secrets into committed JAAS files.

## JAAS configuration

Use [examples/config/jaas.conf](examples/config/jaas.conf) as a starting point. The application chooses the entry name passed to `LoginContext`.

| Module | Configuration and required application work |
| --- | --- |
| `io.mapsmessaging.security.jaas.IdentityLoginModule` | `identityName` plus backend options; callbacks must supply the username, password and `AuthContext`. |
| `io.mapsmessaging.security.jaas.Auth0JwtLoginModule` | `auth0Domain` (host, without scheme), required `audience`; provide the access token through the password callback and the matching requested identity. |
| `io.mapsmessaging.security.jaas.SSLCertificateLoginModule` | Supply certificate-derived principals using `PrincipalCallback` after a trusted TLS handshake; this module does not perform that handshake. |
| Other modules | `AwsCognitoLoginModule`, `Auth0JwtLoginModule`, `AnonymousLoginModule` are distinct implementations. Use the source and matching guide rather than interchanging their configuration. |

`debug` is a JAAS module option. Keep it false for normal deployment. See [authentication](docs/authentication.md) for complete callbacks and cleanup.

## Authorization and stable mappings

`IdentityAccessManager` consumes `authorisationProvider` in its configuration map. Omitting it selects the permissive `OpenAuthorizationProvider`. To enforce permissions, choose the intended provider explicitly and check decisions before operations.

| Property | Meaning |
| --- | --- |
| `authorisationProvider` | `ACL`, `OpenFGA` or `Open` |
| `authorisation.enableCaching` | Nested `authorisation` object; factory default is true when that object exists |
| `authorisation.cachingTime` | Cache duration in seconds; factory default is 10 |
| `passwordHandler` | Simple class name, for example `BCrypt2BPasswordHasher`; IdentityAccessManager defaults to `Pbkdf2Sha512PasswordHasher` |

The dotted names in this table describe nesting; `authorisation` is an object. Stable user/group mapping stores are constructor arguments (`MapStore<UserIdMap>` and `MapStore<GroupIdMap>`), not automatically selected by these properties. See [authorization](docs/authorization.md) for persistence, inheritance and cache boundaries.

### ACL

[acl.json](examples/config/acl.json) supplies `configDirectory` and `certificateStore`.

- Create the policy directory before startup. The provider reads/writes `.acl_enc.dat` there.
- `certificateStore` selects the manager holding the ACL state encryption key. `passphrase` is the key-entry password used by the provider; `store_passphrase` can separately protect the store file.
- Keep the keystore and encrypted policy state together across restarts. Losing the key prevents reading the previous policy state.
- Application permission masks and resource traversal must remain compatible with existing state.

### OpenFGA

[openfga.json](examples/config/openfga.json) contains the exact nested layout:

```text
root
  authorisationProvider: OpenFGA
  authorisation
    openfga
      uris, storeId, modelId, userType, groupType,
      tenantSeparator, groupMemberRelation, connectionTimeout
```

`connectionTimeout` is in seconds (default 10). `uris` is passed as the SDK API URL. Provision the store/model before constructing the provider; the example IDs are placeholders. Permission relation names and resource types must match the deployed authorization model. [The repository model fixture](src/test/resources/openfga-model.json) illustrates the test model, not a universal model for every application.

## Certificate managers and storage

| Manager | Properties |
| --- | --- |
| File keystore | `type` (for example `PKCS12`), `path`, `store_passphrase` with `passphrase` fallback; optional `providerName` |
| PKCS11 | `type=PKCS11`, `configPath`, `providerName`, PIN in `store_passphrase` or `passphrase`; do not add an unrelated file `path` |
| JVM trust store | `passphrase` without file-store/PKCS11 selectors; fallback manager loads `${java.home}/lib/security/cacerts` read-only. It does not select by a `type=JVM` value. |

`providerName=BC` registers Bouncy Castle in the file-store implementation; the selected store is still created through `KeyStore.getInstance(type)`. Do not assume this property pins the JCA implementation.

`CertificateManagerFactory.getManager` creates a manager on each matching factory call; it does not cache manager instances. Retain and coordinate the manager used by your application. Changing a file does not refresh an existing instance; reopening creates another instance, which must not race a stale writer.

Keystore managers can choose a byte store through `store`:

| `store` | Configuration |
| --- | --- |
| `File` | `path` is the file location; this is also the storage factory fallback |
| `AwsSecrets` | `region` (default `us-east-1`), optional explicit `accessKeyId`/`secretAccessKey`; otherwise SDK credential selection; store `path` is used as the secret name |
| `Vault` | `vaultAddress`, `vaultToken`, optional `secretEngine` (default `data`), `sslVerify` (default true) |

AWS/Vault store keystore bytes as Base64, not individual key entries. The current AWS `exists(name)` implementation always returns false; validate any create/load lifecycle that depends on existence before adopting it for persistent keystores. File storage is the runnable examples' path.

## TLS

[tls.json](examples/config/tls.json) shows the two nested store objects expected by `SslHelper.createContext(protocol, config, logger)`.

| Location/key | Meaning |
| --- | --- |
| `keyStore.managerFactory` | JCA KeyManagerFactory algorithm; examples use `KeyManagerFactory.getDefaultAlgorithm()` programmatically |
| `keyStore.passphrase` | Private-key password passed to KeyManagerFactory |
| `keyStore.alias` | Optional fixed key alias |
| `trustStore.managerFactory` | JCA TrustManagerFactory algorithm; examples use `TrustManagerFactory.getDefaultAlgorithm()` |
| root `clientCertificateRequired` | When configuring a server engine, require a client certificate; default false |
| root `clientCertificateWanted` | Request an optional client certificate when it is not required; default false |
| root `crlUrl` | Optional CRL URL; it belongs on the root configuration object |
| root `crlInterval` | CRL refresh interval in milliseconds; default 86,400,000 (24 h) |

The static JSON uses common algorithm names `SunX509` and `PKIX`; verify that they are available on the deployment JVM. The Java example obtains defaults at runtime instead.

The helper does not set a client engine's peer host, endpoint identification algorithm, protocol/cipher allowlists or transport timeouts. See [certificates and TLS](docs/certificates-and-tls.md) for explicit client hostname verification, server mode and mutual-TLS responsibilities.

## Authentication monitoring

Create `AuthenticationMonitorConfig` and pass it through the supported integration path; it is a Java object, not an automatically parsed JSON section.

| Java property | Default | Unit |
| --- | ---: | --- |
| `maxFailuresBeforeLock` | 5 | failures |
| `initialLockSeconds` | 30 | s |
| `maxLockSeconds` | 900 | s |
| `failureDecaySeconds` | 900 | s; non-positive disables decay |
| `enableSoftDelay` | true | boolean |
| `softDelayMillisPerFailure` | 200 | ms |
| `maxSoftDelayMillis` | 2000 | ms |

Monitoring is in-memory. Supply the connection context on each authentication attempt and account for delays in the application's execution model. See [operations](docs/operations.md).
