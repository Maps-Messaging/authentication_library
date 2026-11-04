# Integrating the authentication library

This guide describes the current `development` API (`3.1.0-SNAPSHOT`). Use documentation from the same tag as a released JAR: not every API shown here exists in older releases.

The library supplies security components for an application; it does not start a network listener, supply an HTTP login endpoint, or enforce resource permissions automatically.

## Choose an integration path

| Requirement | Entry points | Guide |
| --- | --- | --- |
| Username/password or token login | JAAS `LoginContext`, `IdentityLoginModule`, `IdentityLookupFactory` | [Authentication](authentication.md) |
| Resource permissions, grants and groups | `IdentityAccessManager`, `AuthorizationProvider`, ACL/OpenFGA | [Authorization](authorization.md) |
| Protocol-level challenge/response | `MapsSecurityProvider`, standard `SaslClient`/`SaslServer` | [SASL](sasl.md) |
| TLS or mutual TLS | `CertificateManagerFactory`, `SslHelper`, JDK sockets/engines | [Certificates and TLS](certificates-and-tls.md) |
| Persistent Ed25519 transport identity and pinned peers | `Ed25519IdentityManager`, `TrustedPeerKeyResolver` | [Certificates and TLS](certificates-and-tls.md), [transport identities](transport-identities.md) |
| Password formats, stores and extension points | `PasswordHandlerFactory`, `Store`, Java `ServiceLoader` | [Operations and extension points](operations.md) |

Start with the [runnable examples](../examples/README.md), then use the [configuration reference](../Config.md) for the selected backend.

## How the components fit

1. Load your application configuration and construct the selected identity backend. Keep passwords, key passphrases and service tokens outside source control.
2. Authenticate the connection using JAAS, SASL or an authenticated TLS peer. Each mechanism has its own callback and identity-mapping requirements.
3. Resolve the authenticated identity and stable user/group IDs. Retain a distinct `Subject` and security context per connection/session.
4. Ask your authorization provider whether that identity may perform the requested permission on the exact tenant/resource.
5. Perform the operation only after an allow decision. Repeat the check at every protected entry point, including list results and metadata.
6. Clean up login, SASL and application connection state when the session ends.

Authentication proves an identity. Authorization decides an operation. TLS protects the transport and may authenticate a certificate. A successful TLS handshake or SASL exchange does not by itself grant application permissions.

## Application responsibilities

| Library provides | Application supplies |
| --- | --- |
| JAAS modules and identity backends | Login entry points, credential acquisition and callback handlers |
| SASL mechanisms | Protocol framing, mechanism negotiation, transport protection and exchange limits |
| ACL/OpenFGA providers | Permission definitions, resource types, tenant boundaries and traversal rules |
| User/group lifecycle hooks | Stable mapping storage and synchronization with the selected policy backend |
| Certificate stores and `SSLContext`/`SSLEngine` helpers | Certificate provisioning, trust policy, client/server mode and hostname verification |
| Log-message enums | Logging backend/configuration and monitoring of failures |

## Startup and deployment

- Package the library and its runtime dependencies, preserving `META-INF/services` entries when shading. Factories use `ServiceLoader` to discover identity, password, policy, certificate and storage implementations.
- Register `MapsSecurityProvider` before creating SASL mechanisms through `javax.security.sasl.Sasl`. Ordinary JAAS logins do not require that registration.
- Select authorization explicitly. `IdentityAccessManager` defaults to `OpenAuthorizationProvider` if `authorisationProvider` is omitted; that provider allows access.
- Provision writable state directories and back up policy data, ID mappings, keystores and trust/pin registries together. Do not regenerate IDs during a normal restart.
- Validate required files, provider selection and initial grants before accepting traffic. Some factories return `null` for an unknown or unusable configuration; check the result.
- Use a new session `Subject` per login. Do not treat provider singleton factories as per-session containers.

## Verification before adopting a configuration

The local examples exercise the library APIs without requiring LDAP, Cognito, Auth0 or OpenFGA. External services, PKCS11 hardware, real network TLS handshakes and deployment permissions need validation in the target environment. The individual guides distinguish a runnable demonstration from a deployment template.

The repository POM currently targets Java 17. Check the Java requirements of the chosen artifact and all runtime dependencies when selecting a release and deployment JDK; a source target alone is not a compatibility certification.

## Further reading

- [Authentication and JAAS](authentication.md)
- [Authorization and identity lifecycle](authorization.md)
- [SASL exchange](sasl.md)
- [Certificates, TLS and pinned identities](certificates-and-tls.md)
- [Configuration reference](../Config.md)
- [Operations, password handling and custom providers](operations.md)
- [Example source and commands](../examples/README.md)
