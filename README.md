# SASL Helpers and implementation
Provides a SASL implementation for both client and server with support for .htpasswd files to start with 

- CRAM-MD5
- DIGEST-MD5
- SCRAM - work in progress

JAAS Login module support for HtPassword files

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
