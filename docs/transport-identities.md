# Ed25519 transport identities

These APIs supply standard Java private and public keys. They have no dependency on a transport library and do not perform session negotiation or record encryption. The existing Java 17 compilation target is retained; the identity tests also run on JDK 25.

## Create a persistent server identity

Use the existing certificate manager configuration. With the default file storage, a missing PKCS12 store is created on the first successful save; an existing store is loaded with its configured password. See the remote-storage limitations below before selecting a different backend.

```java
import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.certificates.CertificateManager;
import io.mapsmessaging.security.certificates.CertificateManagerFactory;
import io.mapsmessaging.security.certificates.CertificateUtils;
import io.mapsmessaging.security.certificates.Ed25519IdentityManager;
import java.time.Duration;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

ConfigurationProperties configuration = new ConfigurationProperties(Map.of(
    "type", "PKCS12",
    "path", "/etc/maps/server-identity.p12",
    "store_passphrase", storePassword));
CertificateManager manager = CertificateManagerFactory.getInstance().getManager(configuration);
Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
provisioner.createIdentity("maps-server", entryPassword,
    new X500Principal("CN=maps-server"), Duration.ofDays(365));
```

`storePassword` is a string from administrator configuration; `entryPassword` is a caller-owned `char[]`. Neither is logged by the provisioning helper. The caller should clear its password arrays when finished. Certificate validity must be positive and expressed in whole seconds. Certificates contain an Ed25519 public key, a secure random positive serial number, `digitalSignature` key usage, and `CA=false`. They are signed using Ed25519. Existing RSA generation is unchanged.

Creation refuses every occupied alias in the loaded keystore, including aliases holding certificates or secret keys. Keystore-specific alias rules apply, including PKCS12 case insensitivity. Provision once during administrator setup, rather than regenerating an identity at each server start. Only new identity provisioning requires PKCS12; the existing manager can load Ed25519 entries from JKS and supported PKCS#11 providers too.

The provisioning helper delegates all persistence to the existing manager and its `StorageFactory`-selected store. It synchronizes on the manager for alias checks and writes. Use a single manager/writer for a store and coordinate other mutations on that monitor; this is not a lock across processes or separately opened managers. Storage and cryptographic failures propagate with their causes. After a reported save failure, the helper removes the newly added in-memory entry. Storage-specific partial writes cannot be undone by this helper; durability and atomic writes remain properties of the configured storage implementation.

Existing remote-storage limitations remain unchanged: `AWSSecretsStore.exists()` always reports false, and `VaultStore.exists()` treats read failures as absence. Those paths can open an empty keystore despite an existing stored identity, bypassing alias checks on that identity. Do not use these backends for identity provisioning until their existence/error handling is corrected. The helper cannot recover durable entries that the manager did not load.

## Load and sign without exporting private keys

```java
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

PrivateKey privateKey = manager.getKey("maps-server", entryPassword);
PublicKey publicKey = manager.getCertificate("maps-server").getPublicKey();

Signature signer = Signature.getInstance("Ed25519");
signer.initSign(privateKey);
signer.update(challenge);
byte[] signature = signer.sign();

Signature verifier = Signature.getInstance("Ed25519");
verifier.initVerify(publicKey);
verifier.update(challenge);
boolean verified = verifier.verify(signature);
```

The existing `CertificateManager` contract is sufficient. No private-key encoding, conversion or extraction is required. Provider-backed key handles pass directly to `Signature`. An unsupported algorithm or incompatible provider must be reported to the administrator, rather than falling back to a different identity or algorithm.

## Exchange public certificates

```java
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

byte[] publicCertificate = provisioner.exportCertificate("maps-server");
Files.write(publicCertificatePath, publicCertificate, StandardOpenOption.CREATE_NEW);
String fingerprint = CertificateUtils.publicKeyFingerprint(publicKey);

Ed25519IdentityManager peerProvisioner = new Ed25519IdentityManager(peerCertificateManager);
peerProvisioner.importTrustedCertificate("maps-server-current", publicCertificate);
```

Export returns DER X.509 bytes, containing only the public certificate. Import accepts exactly one DER or PEM X.509 certificate and rejects occupied aliases and non-Ed25519 keys. Import is an explicit administrator operation; never call it automatically with a remotely presented certificate. Validate exchanged keys through an authenticated administrator channel before authorising their aliases.

Fingerprints are `SHA-256:` followed by lowercase hexadecimal of SHA-256 over the public key's standard SubjectPublicKeyInfo encoding. They are not hashes of the certificate or private key. Renewing a certificate with the same key retains this fingerprint. Providers may name Ed25519 keys `EdDSA`; validation checks the encoded algorithm OID (`1.3.101.112`), so Ed448 is rejected.

## Explicit trust and key rotation

```java
import io.mapsmessaging.security.certificates.TrustedPeerKeyResolver;
import java.util.List;

TrustedPeerKeyResolver trustedPeers = new TrustedPeerKeyResolver(peerCertificateManager, Map.of(
    "warehouse", List.of("warehouse-current", "warehouse-next"),
    "gateway", List.of("gateway-current")));

List<PublicKey> warehouseKeys = trustedPeers.getTrustedKeys("warehouse");
PublicKey currentKey = trustedPeers.getTrustedKey("warehouse-current");
boolean pinned = trustedPeers.isTrusted("warehouse", presentedPublicKey);
```

The map is the explicit allow-list. A certificate merely being present in the store does not authorise it. For a simple alias-based configuration, use the same value for the logical peer name and its sole certificate alias. Unknown peers, unconfigured aliases, missing configured certificates and unexpected algorithms raise `CertificateException`. A different Ed25519 key returns `false` from `isTrusted`. Logical peer names and configured alias strings are matched exactly; use the same configured spelling when looking up aliases.

To rotate a key, import the new certificate under a fresh alias, authorise both aliases for that logical peer during transition, and then replace the resolver configuration to authorise only the new alias. Configuration and returned lists are immutable snapshots. Certificates are resolved on each lookup, so removing a stored certificate is visible to subsequent lookups. A missing or invalid alias causes the entire logical-peer lookup to fail closed, even when other aliases are still usable.

Trust pins public keys. Certificate subject names, self-signatures, validity periods and certificate chains do not grant or revoke that explicit trust. An expired self-signed certificate may still contain an explicitly pinned key. If a deployment also requires certificate lifetime or CA policies, apply those separately. A pin match must be followed by cryptographic proof of possession; matching a key alone does not authenticate a remote process. The consumer must bind the verified key to the configured logical peer.

## keytool alternative

Run the JDK's `keytool` interactively so passwords are not placed in shell history:

```sh
keytool -genkeypair -alias maps-server -keyalg Ed25519 \
  -dname 'CN=maps-server' -validity 365 -storetype PKCS12 \
  -keystore server-identity.p12

keytool -exportcert -alias maps-server -keystore server-identity.p12 \
  -file maps-server.cer

keytool -importcert -alias warehouse-current -storetype PKCS12 \
  -keystore trusted-peers.p12 -file warehouse.cer
```

Use fresh output filenames and aliases, and independently verify the fingerprint before approving imports. Load keytool-created entries through the same `CertificateManager` methods. No CA is required.

## PKCS#11

`Pkcs11Manager` is unchanged. Token administration and supported mechanisms are provider/hardware responsibilities; the new identity creator does not attempt to provision a token. Load an already provisioned identity through `getKey` and `getCertificate` and use the provider's Ed25519 `Signature` implementation if it requires explicit selection. Never require `PrivateKey.getEncoded()` to succeed. Public certificates/keys still need a standard public encoding for export and pinning.

The existing PKCS#11 manager inherits generic stream-based save methods; this change does not alter those persistence methods. Use the provider's token provisioning tools for token entries. PKCS12/JKS trust stores remain suitable for public peer pins alongside a token-held local identity.

The optional `Pkcs11ManagerTest` runs only when `softhsm.cfg` is supplied and the provider is available. Its Ed25519 test also requires provider support for Ed25519 key generation and signatures. It signs with the retrieved provider key and removes its test entry afterwards. Normal CI needs no physical HSM. A skipped provider test is not evidence of token or hardware compatibility.

## Verification

Run on JDK 25 without changing the current compilation target:

```sh
mvn -Prelease -Dmaven.compiler.proc=full \
  -Dtest=Ed25519IdentityTest,TrustedPeerKeyResolverTest,Pkcs11ManagerTest test
mvn -Prelease -Dmaven.compiler.proc=full test
```

The `release` profile selects released Maps dependencies for these test commands; `test` does not publish anything. `maven.compiler.proc=full` explicitly enables the repository's existing Lombok/JMH annotation processors when Maven runs on JDK 25. Existing external-service tests may skip or require their own configuration.
