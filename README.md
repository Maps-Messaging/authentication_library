# MapsMessaging authentication library

Java components for authentication, authorization, SASL, certificate management and TLS. The library can be embedded independently of the MapsMessaging server.

- JAAS login modules and Unix, Apache htpasswd, encrypted-file, LDAP, Cognito and Auth0 identity backends.
- ACL and OpenFGA authorization with application-defined permissions and resources.
- SASL `SCRAM-SHA-256` and `PLAIN` through standard Java SASL APIs.
- File/JVM/PKCS11 certificate stores, TLS helpers, persistent Ed25519 identities and explicit peer-key pinning.

## Start here

1. Read the [integration overview](docs/overview.md) to choose the components your application needs.
2. Build and run the [complete examples](examples/README.md).
3. Configure the selected [identity, policy and certificate providers](Config.md).

| Guide | Contents |
| --- | --- |
| [Authentication](docs/authentication.md) | JAAS login, callbacks, identity backends, Subjects and failure handling |
| [Authorization](docs/authorization.md) | Permissions, resources, grants, groups, inheritance and persistence |
| [SASL](docs/sasl.md) | Client/server exchange, mechanism policies and integration requirements |
| [Certificates and TLS](docs/certificates-and-tls.md) | Keystores, truststores, TLS/mTLS and transport identities |
| [Operations and extension points](docs/operations.md) | Password formats, ID storage, lockouts, logging and custom providers |
| [Configuration](Config.md) | Actual property names and copyable configuration templates |

## Maven coordinates

Use a version published in your selected repository:

```xml
<dependency>
  <groupId>io.mapsmessaging</groupId>
  <artifactId>authentication_library</artifactId>
  <version>3.1.0-SNAPSHOT</version>
</dependency>
```

The examples document the current development API, including APIs absent from older releases. Snapshot resolution requires the MapsMessaging snapshot repository; see [example setup](examples/README.md). Release artifacts are available from [Maven Central](https://central.sonatype.com/search?smo=true&q=io.mapsmessaging%3Aauthentication_library). Select a release version explicitly rather than assuming the development snapshot is published there.

`PLAIN` carries password material and requires a protected transport such as TLS. SASL authentication does not supply a transport encryption layer in this implementation. Resource authorization must be invoked by the embedding application.

## License and project

See [LICENSE](LICENSE): Apache License 2.0 with the Commons Clause. Review the complete license when embedding or distributing the library.

[Buildkite](https://buildkite.com/mapsmessaging/040-authentication-and-authorisation-library-snapshot-build) · [SonarCloud](https://sonarcloud.io/summary/new_code?id=Authentication_Library) · [DeepWiki](https://deepwiki.com/Maps-Messaging/authentication_library)
