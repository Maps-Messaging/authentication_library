# Certificates, TLS and transport identities

The library loads certificate stores, builds JSSE `SSLContext` instances and supplies keys for transport signatures.
The host application owns sockets, protocol framing, authentication decisions and authorization. Creating a context does
not open a listener, establish a connection or authenticate an application user.

The complete Java examples are [TlsExample.java](../examples/java/TlsExample.java) and
[TransportIdentityExample.java](../examples/java/TransportIdentityExample.java). They use the library's existing APIs
and explicit types. Compile them against the built library and its runtime dependencies; they are external integration
examples, outside Maven's normal `src/main/java` compilation. Use the [shared build instructions](../examples/README.md#build-against-this-checkout); commands below assume `$CLASSPATH` is set as shown in that guide. Password environment variables are supplied by the operator; the examples do not expand secrets
inside YAML or log passwords.

## Select and load a certificate manager

`CertificateManagerFactory.getInstance().getManager(configuration)` walks the registered `CertificateManager`
services and creates the first matching implementation. Pass the individual store configuration, rather than the
whole TLS configuration. The standard file-backed manager accepts:

| Key | Meaning |
| --- | --- |
| `type` | Java keystore type, such as `PKCS12` or `JKS`. |
| `path` | Store location; with default storage, a filesystem path. |
| `store_passphrase` | Password used to load and save the store. |
| `passphrase` | Store-password fallback when `store_passphrase` is absent; also the private-entry password used by `SslHelper`. |
| `providerName` | `BC` registers Bouncy Castle; the generic manager still calls `KeyStore.getInstance(type)` without selecting a provider explicitly. |

The default storage is a file. A configured file path that does not yet exist initializes an empty store; it is persisted on a successful mutation. Omitting the `path` property does not select the file-backed manager.
Loading a manager does not generate certificates or create a usable TLS identity. Check that deployed paths exist so a
misspelling does not silently become an empty trust or identity store. Storage backends are selected by `StorageFactory`;
see [transport-identities.md](transport-identities.md) for remote provisioning and durability limitations.

Use `getAliases()`, `getCertificate(alias)` and `getKey(alias, entryPassword)` to inspect and load entries. To install a
provisioned identity, call `addPrivateKey(alias, entryPassword, privateKey, certificateChain)`, with the leaf certificate
first and its issuing chain following. `addCertificate(alias, certificate)` installs a public certificate. These generic
mutation methods save the store and can replace existing entries; implement administrator policy before calling them.
The Ed25519 provisioning helper described below refuses occupied aliases instead.

## Provision TLS material

For production, provision certificates using the deployment's PKI, with the intended DNS/IP subject alternative names,
key usages and issuing chain. Import the private key plus certificate chain into the identity store; put the intended CA
trust anchors, or deliberately trusted self-signed certificates, into the separate trust store. Trust decisions must be
made through an authenticated administrator process.

For a local bootstrap demonstration, `CertificateUtils.generateSelfSignedCertificateSecret("localhost")` returns a
`CertificateWithPrivateKey`. Despite its name this is an RSA private key and X.509 certificate, rather than a symmetric
secret. The certificate has a DNS SAN for the supplied host, server/client authentication purposes and a one-year
lifetime. Install it with `addPrivateKey`; independently authenticate and install its public certificate on the peer
before connecting. Generation alone does not make a peer trust the certificate. This helper is a bootstrap mechanism,
not a CA enrollment, certificate rotation or production trust policy. For IP endpoints, provision matching IP SANs using
the deployment PKI rather than treating an IP address as the helper's DNS SAN.

A keytool-generated local demonstration avoids writing bootstrap code:

```sh
keytool -genkeypair -alias tls-identity -keyalg RSA -keysize 3072 \
  -dname 'CN=localhost' -ext 'SAN=dns:localhost' -validity 30 \
  -storetype PKCS12 -keystore identity.p12
keytool -exportcert -alias tls-identity -keystore identity.p12 -file localhost.cer
keytool -importcert -alias localhost-demo -storetype PKCS12 \
  -keystore trust.p12 -file localhost.cer
```

Enter passwords interactively. Authenticate the exported certificate before approving the import. For this local
example set `TLS_STORE_PASSWORD` to the identity-store password, `TLS_KEY_PASSWORD` to its key-entry password, and
`TLS_TRUST_PASSWORD` to the trust-store password. Some PKCS12 tools/providers require the entry and store passwords
to be the same; use the actual passwords supported by the chosen tooling.

## Build a TLS context with nested properties

`TlsExample.createContext` builds this shape in Java:

```yaml
keyStore:
  type: PKCS12
  path: identity.p12
  store_passphrase: '<identity store password>'
  passphrase: '<private key entry password>'
  alias: tls-identity
  managerFactory: SunX509
trustStore:
  type: PKCS12
  path: trust.p12
  store_passphrase: '<trust store password>'
  passphrase: '<trust store password>'
  managerFactory: PKIX
# Optional ROOT properties, not children of trustStore:
# crlUrl: https://pki.example/crl.der
# crlInterval: 3600000
```

`SunX509` and `PKIX` are common JDK algorithms; the example uses `KeyManagerFactory.getDefaultAlgorithm()` and
`TrustManagerFactory.getDefaultAlgorithm()` for the current runtime. The YAML shows the property shape, not an automatic
loader: `SslHelper` casts `keyStore` and `trustStore` values to `ConfigurationProperties`, so construct those nested
objects explicitly or verify the host configuration loader produces them. Plain nested `Map` values are insufficient.

`store_passphrase` opens the file; `passphrase` initializes `KeyManagerFactory` and unlocks private key entries. Configure
both explicitly when they differ. `alias` wraps X.509 key managers to select that identity; it is not a certificate-name
or hostname check. Ensure the alias contains a private key and suitable chain. Leaving it out delegates selection to JSSE.
Both store objects are required by the current helper, including for client contexts.

The example requests `TLSv1.3`; availability depends on the installed runtime/provider. It uses a pre-provisioned local
identity, which also allows a server to request a client certificate:

```sh
java -cp "$CLASSPATH" TlsExample identity.p12 trust.p12 tls-identity localhost 8443
```

This command connects to an already running TLS server and performs a handshake. It creates no server. The certificate
must match `localhost`, and `trust.p12` must trust the server. For distinct client and server identities, provision and
configure each endpoint separately and install the corresponding issuer trust on the other endpoint.

## Hostname checks and mutual TLS are host responsibilities

The socket example enables endpoint identification with `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`
before handshaking. Context construction alone does not enable hostname verification. For a client engine, use
`context.createSSLEngine(host, port)`, set client mode, and apply endpoint identification to its SSL parameters. Supplying
a peer host without endpoint identification does not by itself require a hostname match.

`TlsExample.createMutualTlsServerEngine` demonstrates `SslHelper.createSSLEngine` with these engine properties:

| Key | Effect |
| --- | --- |
| `clientCertificateRequired: true` | Requires a client certificate; takes precedence over `clientCertificateWanted`. |
| `clientCertificateWanted: true` | Requests a certificate when `Required` is false; does not require one. |
| Both false or absent | Does not request a client certificate. |

Set `engine.setUseClientMode(false)` for a server; set it to `true` for a client. The host owns the engine handshake,
wrap/unwrap loop, delegated tasks, buffer sizing and connection closure. Socket servers must configure their sockets'
client-auth requirements separately. A verified certificate establishes TLS peer credentials; mapping those credentials
to a user/role and enforcing permissions remain application responsibilities. Neither optional client authentication
nor a successful context construction proves that a remote client is authenticated.

## CRL configuration and limits

The implementation reads `crlUrl` and `crlInterval` from the root configuration passed to `createContext`, despite older
API comments describing `crlUrl` under `trustStore`. `crlInterval` is milliseconds, defaulting to 86400000 (24 hours).
The wrapper first invokes the configured trust manager and then checks each supplied certificate against the downloaded
CRL. It does not replace configured trust anchors with JVM defaults.

CRLs load lazily during validation and refresh on later validations after the interval. Fetch failures are logged. An
initial failure leaves no CRL and validation fails through `CrlTrustManager`; after a successful load, a later fetch
failure can leave the previous CRL in use. The downloader does not verify the CRL signature, issuer or freshness dates,
and does not set explicit connection/read timeouts. Do not describe this facility as a complete revocation policy. The
host/deployment must assess the source, availability and revocation requirements before enabling it.

## JVM and PKCS#11 stores

A store configuration containing `passphrase` without generic file-store keys falls through to `JvmKeyStoreManager`.
It loads `${java.home}/lib/security/cacerts` with the JVM default keystore type. Supply its actual password; do not assume
that `javax.net.ssl.trustStore` changes this path. The manager rejects its mutation/save methods. To use it as the TLS
trust store, supply `passphrase` and the trust-manager `managerFactory`, omitting `type` and `path`.

For a token identity use `type: PKCS11`, `providerName: SunPKCS11` (or the installed configurable provider), `configPath`
pointing to the provider configuration file, and `passphrase` containing the PIN. Add the key-manager `managerFactory`
and optional `alias` for `SslHelper`. Omit `path`: with the shipped service ordering, `type` + `path` + password would
match the generic file manager first. The provider must already be installed; the PKCS#11 manager configures it and
loads the token with the PIN. Token provisioning, permissions, mechanism support and availability belong to the provider
and hardware. The manager inherits stream-save operations; do not use those as token provisioning tools. Keep public
trust anchors in a separate file/JVM trust store. A software-store example or a skipped token test is not hardware
compatibility evidence.

## Ed25519 transport identity integration

Transport signature identities use a different trust model from TLS certificate-chain validation. See
[transport-identities.md](transport-identities.md) for the full API contract and storage caveats.

`TransportIdentityExample` provides two explicit administrator commands. Set `IDENTITY_STORE_PASSWORD` for the store
being opened; provisioning also needs `IDENTITY_KEY_PASSWORD` for the new private entry:

```sh
java -cp "$CLASSPATH" TransportIdentityExample provision local-identity.p12 local-identity local-public.cer
# Authenticate local-public.cer's public-key fingerprint through the administrator channel first.
java -cp "$CLASSPATH" TransportIdentityExample import-peer peer-pins.p12 warehouse-current local-public.cer
```

These filenames illustrate exporting one identity and trusting it as logical peer `warehouse` at another endpoint.
Use each endpoint's own stores. `provision` generates a persistent Ed25519 identity once, exports only its public DER
certificate with `CREATE_NEW`, and prints the public-key fingerprint. If export fails after provisioning, the identity
remains saved; export it using `Ed25519IdentityManager.exportCertificate` rather than rerunning provisioning. Both
provisioning and import refuse occupied aliases. Password arrays created by the example are cleared after use; immutable
configuration/environment strings remain managed by the JVM and deployment.

At runtime, open the local identity store and call `sign` with the private alias and entry password. Open the public
peer store and construct `trustedPeers`; the sample registry authorizes only `warehouse -> warehouse-current`.
The `verify` method requires both a pin match and a valid Ed25519 signature. Callers must supply a protocol-defined
transcript that binds the intended peer, both roles, fresh challenges and session context; a reusable signed byte string
alone does not provide replay protection or authenticate an entire session. These methods do not negotiate/encrypt a
transport or define a wire protocol.

A certificate's presence, subject, issuer or self-signature does not authorize a peer. The administrator registry is an
explicit allow-list. Unknown peers, unconfigured aliases, missing entries and non-Ed25519 certificates fail with
exceptions; a different valid Ed25519 key returns false. Certificate validity dates and CA chains are not evaluated by
this pin resolver. Apply additional lifetime/CA policy separately when required. A public-key match still needs proof
of possession, provided by signature verification over the agreed transcript.

For rotation, import the next key under a new alias, build a new resolver mapping the peer to both current and next
aliases during transition, then replace it with a resolver authorizing only the next alias. The registry is copied at
construction. Certificates are resolved on every lookup; any missing/invalid configured alias makes that peer's lookup
fail closed. Coordinate mutations using the shared manager monitor and a single manager/writer per store; there is no
cross-process lock.
