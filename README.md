# SASL Helpers and implementation
Provides a SASL implementation for both client and server with support for .htpasswd files to start with 

- CRAM-MD5
- DIGEST-MD5
- SCRAM - work in progress

JAAS Login module support for HtPassword files

# pom.xml setup

Add the repository configuration into the pom.xml
``` xml
    <!-- MapsMessaging jfrog server --> 
    <repository>
      <id>mapsmessaging.io</id>
      <name>artifactory-releases</name>
      <url>https://mapsmessaging.jfrog.io/artifactory/mapsmessaging-mvn-prod</url>
    </repository>
```    

Then include the dependency
``` xml
     <!-- Non Blocking Task Queue module -->
    <dependency>
      <groupId>io.mapsmessaging</groupId>
      <artifactId>SaslHelper</artifactId>
      <version>1.0.0</version>
    </dependency>
```   

