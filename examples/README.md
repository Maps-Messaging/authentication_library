# Complete integration examples

These examples target the source API in this checkout, `3.1.0-SNAPSHOT`. They are separate from the production Maven source tree and do not start a MapsMessaging server.

## Build against this checkout

Run from the repository root with Maven and a JDK compatible with the library and its runtime dependencies:

```sh
mvn -Psnapshot -DskipTests -Dgpg.skip=true -Ddependency-check.skip=true install
mvn -f examples/pom.xml package dependency:copy-dependencies -DincludeScope=runtime
```

The first command installs the local development artifact without executing the library's tests. Omit `-DskipTests` to run them; some integration tests require external services or credentials. Neither command publishes or deploys an artifact.

The examples POM explicitly includes the snapshot configuration/logging dependencies, which the library declares in its snapshot profile. If adopting a release, change versions together to the dependencies appropriate to that release and use its matching documentation.

## Run the local demonstrations

On Linux/macOS:

```sh
export CLASSPATH='examples/target/classes:examples/target/dependency/*'
java -cp "$CLASSPATH" AuthenticationExample
java -cp "$CLASSPATH" AuthorizationExample
java -cp "$CLASSPATH" SaslExample
java -cp "$CLASSPATH" PasswordExample
```

On Windows PowerShell:

```powershell
$env:CLASSPATH = 'examples/target/classes;examples/target/dependency/*'
java -cp $env:CLASSPATH AuthenticationExample
java -cp $env:CLASSPATH AuthorizationExample
java -cp $env:CLASSPATH SaslExample
java -cp $env:CLASSPATH PasswordExample
```

Use `;` instead of `:` as the Java classpath separator on Windows. The demonstration usernames/passwords belong only to the local examples.

| Source | What it demonstrates | External requirements |
| --- | --- | --- |
| [AuthenticationExample.java](java/AuthenticationExample.java) | Apache identity backend, JAAS callbacks and login lifecycle | Local temporary files only |
| [AuthorizationExample.java](java/AuthorizationExample.java) | Custom permissions/traversal, encrypted ACL state and allow/deny checks | Local temporary files only |
| [SaslExample.java](java/SaslExample.java) | Complete in-process SCRAM exchange and authorization callback | None |
| [PasswordExample.java](java/PasswordExample.java) | SHA-512-crypt hashing, stored-format parsing and password verification | None |
| [TlsExample.java](java/TlsExample.java) | Certificate/trust stores, TLS connection and hostname verification | Provisioned PKCS12 files and a listening TLS server |
| [TransportIdentityExample.java](java/TransportIdentityExample.java) | Separate provisioning, peer import and runtime proof APIs | Writable keystore, certificate file and configured passphrases |

See [certificates and TLS](../docs/certificates-and-tls.md) for executable provisioning commands, environment variables and TLS/identity arguments. The TLS example connects to your supplied host; it does not create a server or bypass validation.

## Configuration templates

- [jaas.conf](config/jaas.conf): JAAS entries for Apache password, certificate-principal and Auth0 JWT login.
- [apache.json](config/apache.json): explicit Apache identity file paths.
- [acl.json](config/acl.json): ACL provider and encrypted policy-state key store.
- [openfga.json](config/openfga.json): external OpenFGA connection/model mapping.
- [tls.json](config/tls.json): nested identity/trust stores and mutual-TLS policy.

These are templates, not files automatically discovered by the library. The Java examples construct configuration explicitly; an embedding application chooses its own JSON/YAML loader and passes the corresponding map to the selected factory. Replace every `REPLACE_WITH_...` field before use and inject secrets through the application's secret mechanism. The supplied templates contain no working service credentials.

To use the Apache JAAS template with your application, provision local identity files first:

```sh
mkdir -p examples/config/apache
printf 'alice:' > examples/config/apache/.htpassword
openssl passwd -6 >> examples/config/apache/.htpassword
printf 'operators: alice\n' > examples/config/apache/.htgroups
```

`openssl passwd -6` prompts for the password and generates a SHA-512-crypt value. These commands create/replace the example password file; adapt them before managing an existing database. OpenSSL is an external provisioning utility, not part of this library. The current example uses SHA-512-crypt because the verification findings in [operations](../docs/operations.md#password-verification-findings) affect bcrypt/PBKDF2 in this checkout; it is not a recommendation to downgrade an existing credential policy. Point your application's JAAS configuration at `examples/config/jaas.conf` (for example with `-Djava.security.auth.login.config=examples/config/jaas.conf`) and implement the callbacks shown in the authentication guide.

## Expected results and limits

A successful local example exits normally and prints a short success message. The minimal consumer POM does not select an SLF4J backend, so you may see a no-provider/NOP warning; configure your application's backend before relying on library logs, as described in [operations](../docs/operations.md#logging-and-failures). Login/authorization examples deliberately check both accepted and rejected operations. A missing provider, unexpected decision or failed exchange throws an exception instead of silently succeeding.

Executing the local examples does not validate your LDAP/Cognito/Auth0/OpenFGA deployment, your external TLS endpoint or a PKCS11 device. The guides identify the application responsibilities and backend-specific checks needed for those integrations.
