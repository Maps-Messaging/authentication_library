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

# Access Control List (ACL) Entry Format

ACL entry strings follow the format "identifier = access" where:

- The identifier represents a username or group name with an optional `[authDomain:]username[remoteHost]` specifier.
    - The `[authDomain:]` prefix represents an optional authentication domain.
    - The `username` component represents the username.
    - The `[remoteHost]` suffix represents an optional remote host specification enclosed in square brackets.
- The access control string specifies the allowed actions using keywords determined by the provided AccessControlMapping implementation.
    - Multiple access control keywords can be separated by the `|` (pipe) character.

## Identifier Format

The identifier follows the syntax `[authDomain:]username[remoteHost]`, where:

- `[authDomain:]` (optional): Represents an authentication domain. Use a colon (":") to separate the authDomain from the username.
- `username`: Represents the username component. It can include alphanumeric characters and special characters.
- `[remoteHost]` (optional): Represents the remote host specification. Enclose the remote host in square brackets ("[]").

### Examples

- `john.doe`: Represents a username without any authentication domain or remote host.
- `ldap:john.doe`: Represents a username with the "ldap" authentication domain and no remote host.
- `unix:admin[localhost]`: Represents a username with the "unix" authentication domain and a remote host specified as "localhost".

## Access Control String

The access control string specifies the allowed actions using keywords determined by the provided AccessControlMapping implementation. Multiple access control keywords can be
separated by the `|` (pipe) character.

### Examples

- `Read`: Allows the "Read" action.
- `Write|Create`: Allows both "Write" and "Create" actions.

## ACL Entry Example

Here's an example ACL entry string:

> ldap:john.doe[localhost] = Read|Write|Create

In this example, the identifier represents a username with the "ldap" authentication domain and a remote host specified as "localhost". The access control string allows the "
Read", "Write", and "Create" actions.


---

By following the ACL entry format described above, you can define access control rules for your application based on the provided AccessControlMapping implementation.

Please refer to the documentation of the AccessControlMapping class for the specific access control keywords used in your implementation.

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

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/summary/new_code?id=Authentication_Library)
