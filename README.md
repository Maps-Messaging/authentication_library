# SASL Helpers and implementation

This Java library provides a simple and secure way to authenticate users using the Simple Authentication and Security Layer (SASL) protocol, including the SCRAM family of
mechanisms. It also includes support for multiple identity backends, including Linux passwd files and htpasswd.

The library includes implementations for the following SASL mechanisms:

* PLAIN
* CRAM-MD5
* DIGEST-MD5
* SCRAM-SHA-1
* SCRAM-SHA-256
* SCRAM-SHA-512

Applications can also implement custom SASL mechanisms using the library's APIs.

The identity backends enable applications to authenticate users based on their username and password, with support for multiple backend types, including Linux passwd files and
htpasswd files. This allows applications to leverage existing user databases and authentication services without having to implement custom authentication code.

The library is easy to use and well-documented, with examples and sample code provided to help developers get started. It is also actively maintained and updated, with bug fixes
and new features added on a regular basis.

If you're looking for a robust and flexible SASL authentication library for your Java project, with support for the latest SCRAM mechanisms and multiple identity backends, give
this library a try!

# pom.xml setup

All MapsMessaging libraries are hosted on the [maven central server.](https://central.sonatype.com/search?smo=true&q=mapsmessaging)

Include the dependency

``` xml
     <!-- Authentication module -->
    <dependency>
      <groupId>io.mapsmessaging</groupId>
      <artifactId>AuthenticationLibrary</artifactId>
      <version>0.2.6</version>
    </dependency>
```   

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/summary/new_code?id=Authentication_Library)
