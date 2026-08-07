# SASL and JAAS Implementations

This Java library is designed to provide a robust and easy-to-integrate solution for user authentication and
authorization in various environments. Targeted at developers and system administrators, it simplifies implementing
security protocols in Java applications.

## Features

* Implements the registered `SCRAM-SHA-256` mechanism defined by RFC 7677 and the `PLAIN` mechanism defined by RFC
  4616. `PLAIN` must be used only over a protected transport such as TLS.
* Compatibility with multiple identity backends like Linux passwd files, htpasswd, and others.
* Implements the JAAS standard for authentication using various methods including UNIX, Apache Basic Auth, AWS Cognito,
  Auth0, and LDAP.
* Provides a generic ACL for resource access authorization.

Want to dive deeper?
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Maps-Messaging/authentication_library)

## Getting Started

To quickly integrate this library into your Java project, follow these steps:

1. Add the library to your project's dependency list.
2. Initialize the SASL authentication mechanism.
3. Configure the identity backend.
   A simple example is provided below to help you get started.

## Detailed Usage

For detailed usage instructions and examples, refer to the [Usage Guide](Config.md).

## Supported Identity Backends

The library supports a variety of identity backends, enabling flexible integration with different systems. For each
backend, specific configuration might be required. Below is a list of supported backends:

- Linux passwd files
- Apache htpasswd
- AWS-Cognito
- Auth0
- Ldap
- Easy to extend to other servers


# pom.xml setup

All MapsMessaging libraries are hosted on the [maven central server.](https://central.sonatype.com/search?smo=true&q=mapsmessaging)

Include the dependency

``` xml
     <!-- Authentication module -->
    <dependency>
      <groupId>io.mapsmessaging</groupId>
      <artifactId>AuthenticationLibrary</artifactId>
      <version>1.0.4</version>
    </dependency>
```   

[![Build status](https://badge.buildkite.com/4fe7fb40cfdb2f718310fbc030aa1e9f0df618201fa21f9736.svg)](https://buildkite.com/mapsmessaging/040-authentication-and-authorisation-library-snapshot-build)

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/summary/new_code?id=Authentication_Library)
