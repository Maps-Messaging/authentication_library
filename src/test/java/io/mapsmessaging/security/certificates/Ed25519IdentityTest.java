/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 * Licensed under the Apache License, Version 2.0 with the Commons Clause.
 */
package io.mapsmessaging.security.certificates;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.certificates.keystore.KeyStoreManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class Ed25519IdentityTest {

  private static final char[] ENTRY_PASSWORD = "identity-entry-password".toCharArray();
  private static final X500Principal SUBJECT = new X500Principal("CN=maps-server");
  private static final Duration VALIDITY = Duration.ofDays(30);

  @TempDir
  Path temporaryDirectory;

  @Test
  void generatesDistinctEd25519KeysAndSelfSignedCertificates() throws Exception {
    CertificateWithPrivateKey identity = CertificateUtils.generateEd25519Identity(SUBJECT, VALIDITY);
    CertificateWithPrivateKey otherIdentity = CertificateUtils.generateEd25519Identity(SUBJECT, VALIDITY);
    X509Certificate certificate = (X509Certificate) identity.getCertificate();
    certificate.checkValidity();
    certificate.verify(certificate.getPublicKey());
    assertEquals("1.3.101.112", certificate.getSigAlgOID());
    assertEquals(SUBJECT, certificate.getSubjectX500Principal());
    assertEquals(SUBJECT, certificate.getIssuerX500Principal());
    assertEquals(VALIDITY.toMillis(), certificate.getNotAfter().getTime() - certificate.getNotBefore().getTime());
    assertTrue(certificate.getSerialNumber().signum() > 0);
    assertEquals(-1, certificate.getBasicConstraints());
    assertTrue(certificate.getKeyUsage()[0]);
    assertFalse(certificate.getKeyUsage()[2]);
    assertNotEquals(certificate.getSerialNumber(), ((X509Certificate) otherIdentity.getCertificate()).getSerialNumber());
    assertFalse(MessageDigest.isEqual(certificate.getPublicKey().getEncoded(), otherIdentity.getCertificate().getPublicKey().getEncoded()));
    verifyChallenge(identity.getPrivateKey(), certificate.getPublicKey());
  }

  @Test
  void rejectsInvalidValidityAndSubject() {
    assertThrows(IllegalArgumentException.class, () -> CertificateUtils.generateEd25519Identity(SUBJECT, Duration.ZERO));
    assertThrows(IllegalArgumentException.class, () -> CertificateUtils.generateEd25519Identity(SUBJECT, Duration.ofSeconds(-1)));
    assertThrows(IllegalArgumentException.class, () -> CertificateUtils.generateEd25519Identity(SUBJECT, Duration.ofNanos(1)));
    assertThrows(IllegalArgumentException.class, () -> CertificateUtils.generateEd25519Identity(null, VALIDITY));
    assertThrows(IllegalArgumentException.class, () -> CertificateUtils.generateEd25519Identity(SUBJECT, null));
  }

  @Test
  void persistsAndReloadsThroughExistingCertificateManager() throws Exception {
    Path storePath = temporaryDirectory.resolve("identity.p12");
    CertificateManager manager = openManager(storePath, "PKCS12");
    assertFalse(manager.getExists());
    CertificateWithPrivateKey created = new Ed25519IdentityManager(manager).createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY);
    CertificateManager reloaded = openManager(storePath, "PKCS12");
    assertTrue(reloaded.getExists());
    assertEquals(created.getCertificate(), reloaded.getCertificate("server"));
    verifyChallenge(reloaded.getKey("server", ENTRY_PASSWORD), reloaded.getCertificate("server").getPublicKey());
  }

  @Test
  void exportsOnlyPublicCertificateAndImportsIntoExistingStore() throws Exception {
    CertificateManager local = openManager(temporaryDirectory.resolve("local.p12"), "PKCS12");
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(local);
    provisioner.createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY);
    byte[] exported = provisioner.exportCertificate("server");
    X509Certificate publicCertificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(exported));
    assertArrayEquals(local.getCertificate("server").getEncoded(), exported);
    CertificateManager peers = openManager(temporaryDirectory.resolve("peers.p12"), "PKCS12");
    Ed25519IdentityManager importer = new Ed25519IdentityManager(peers);
    importer.importTrustedCertificate("server-current", exported);
    CertificateManager reloadedPeers = openManager(temporaryDirectory.resolve("peers.p12"), "PKCS12");
    assertEquals(publicCertificate, reloadedPeers.getCertificate("server-current"));
    assertFalse(reloadedPeers.getKeyStore().isKeyEntry("server-current"));
    assertThrows(CertificateException.class, () -> reloadedPeers.getKey("server-current", ENTRY_PASSWORD));
    String expectedFingerprint = "SHA-256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicCertificate.getPublicKey().getEncoded()));
    assertEquals(expectedFingerprint, CertificateUtils.publicKeyFingerprint(publicCertificate.getPublicKey()));
    importer.importTrustedCertificate("server-next", exported);
    assertEquals(2, peers.getAliases().size());
  }

  @Test
  void refusesIdentityAndCertificateOverwritesIncludingCaseCollisions() throws Exception {
    Path storePath = temporaryDirectory.resolve("identity.p12");
    CertificateManager manager = openManager(storePath, "PKCS12");
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
    provisioner.createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY);
    byte[] originalStore = Files.readAllBytes(storePath);
    byte[] exported = provisioner.exportCertificate("server");
    assertThrows(KeyStoreException.class, () -> provisioner.createIdentity("SERVER", ENTRY_PASSWORD, SUBJECT, VALIDITY));
    assertThrows(KeyStoreException.class, () -> provisioner.importTrustedCertificate("server", exported));
    assertArrayEquals(originalStore, Files.readAllBytes(storePath));
    provisioner.importTrustedCertificate("peer", exported);
    assertThrows(KeyStoreException.class, () -> provisioner.createIdentity("peer", ENTRY_PASSWORD, SUBJECT, VALIDITY));
    assertThrows(KeyStoreException.class, () -> provisioner.importTrustedCertificate("PEER", exported));
    assertEquals(2, manager.getAliases().size());
    assertEquals(manager.getCertificate("server"), openManager(storePath, "PKCS12").getCertificate("server"));
  }

  @Test
  void rejectsBlankAliasesNullPasswordAndMalformedCertificates() throws Exception {
    CertificateManager manager = openManager(temporaryDirectory.resolve("identity.p12"), "PKCS12");
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
    assertThrows(KeyStoreException.class, () -> provisioner.createIdentity(" ", ENTRY_PASSWORD, SUBJECT, VALIDITY));
    assertThrows(KeyStoreException.class, () -> provisioner.createIdentity(null, ENTRY_PASSWORD, SUBJECT, VALIDITY));
    assertThrows(KeyStoreException.class, () -> provisioner.createIdentity("server", null, SUBJECT, VALIDITY));
    assertThrows(CertificateException.class, () -> provisioner.importTrustedCertificate("peer", new byte[] {1, 2, 3}));
    assertTrue(manager.getAliases().isEmpty());
  }

  @Test
  void rejectsUnexpectedPublicKeyAlgorithmsOnImportAndExport() throws Exception {
    CertificateManager manager = openManager(temporaryDirectory.resolve("peers.p12"), "PKCS12");
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
    CertificateWithPrivateKey rsa = CertificateUtils.generateSelfSignedCertificateSecret("maps.example");
    manager.addCertificate("rsa", rsa.getCertificate());
    assertThrows(CertificateException.class, () -> provisioner.importTrustedCertificate("peer", rsa.getCertificate().getEncoded()));
    assertThrows(CertificateException.class, () -> provisioner.exportCertificate("rsa"));
    KeyPair ed448 = KeyPairGenerator.getInstance("Ed448").generateKeyPair();
    Certificate ed448Certificate = certificateFor(ed448);
    assertThrows(CertificateException.class, () -> provisioner.importTrustedCertificate("ed448", ed448Certificate.getEncoded()));
    assertEquals(1, manager.getAliases().size());
  }

  @Test
  void propagatesSaveFailureAndRemovesUnpersistedEntries() throws Exception {
    Path storePath = temporaryDirectory.resolve("unwritable.p12");
    CertificateManager manager = openManager(storePath, "PKCS12");
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
    Files.createDirectory(storePath);
    CertificateException creationFailure = assertThrows(CertificateException.class,
        () -> provisioner.createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY));
    assertTrue(creationFailure.getCause() instanceof IOException);
    assertFalse(manager.getKeyStore().containsAlias("server"));
    CertificateWithPrivateKey peer = CertificateUtils.generateEd25519Identity(SUBJECT, VALIDITY);
    CertificateException importFailure = assertThrows(CertificateException.class,
        () -> provisioner.importTrustedCertificate("peer", peer.getCertificate().getEncoded()));
    assertTrue(importFailure.getCause() instanceof IOException);
    assertFalse(manager.getKeyStore().containsAlias("peer"));
    Files.delete(storePath);
    provisioner.createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY);
    assertNotNull(openManager(storePath, "PKCS12").getCertificate("server"));
  }

  @Test
  void removesUnpersistedEntriesWhenStorageThrowsUncheckedFailures() throws Exception {
    RuntimeFailingSaveManager manager = new RuntimeFailingSaveManager(new ConfigurationProperties(Map.of(
        "type", "PKCS12", "path", temporaryDirectory.resolve("failed.p12").toString(), "passphrase", "store-password")));
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
    RuntimeException failure = assertThrows(IllegalStateException.class,
        () -> provisioner.createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY));
    assertSame(manager.failure, failure);
    assertFalse(manager.getKeyStore().containsAlias("server"));
    CertificateWithPrivateKey peer = CertificateUtils.generateEd25519Identity(SUBJECT, VALIDITY);
    RuntimeException importFailure = assertThrows(IllegalStateException.class,
        () -> provisioner.importTrustedCertificate("peer", peer.getCertificate().getEncoded()));
    assertSame(manager.failure, importFailure);
    assertFalse(manager.getKeyStore().containsAlias("peer"));
  }

  @Test
  void propagatesMissingAliasesAndIncorrectPasswords() throws Exception {
    Path storePath = temporaryDirectory.resolve("identity.p12");
    CertificateManager manager = openManager(storePath, "PKCS12");
    Ed25519IdentityManager provisioner = new Ed25519IdentityManager(manager);
    provisioner.createIdentity("server", ENTRY_PASSWORD, SUBJECT, VALIDITY);
    assertThrows(CertificateException.class, () -> manager.getKey("missing", ENTRY_PASSWORD));
    assertThrows(CertificateException.class, () -> provisioner.exportCertificate("missing"));
    CertificateException failure = assertThrows(CertificateException.class, () -> manager.getKey("server", "incorrect".toCharArray()));
    assertNotNull(failure.getCause());
    assertThrows(IOException.class, () -> CertificateManagerFactory.getInstance().getManager(new ConfigurationProperties(
        Map.of("type", "PKCS12", "path", storePath.toString(), "passphrase", "incorrect"))));
  }

  @ParameterizedTest
  @ValueSource(strings = {"PKCS12", "JKS"})
  void existingManagersLoadEd25519AndRsaEntriesTogether(String type) throws Exception {
    Path storePath = temporaryDirectory.resolve("existing." + type);
    CertificateManager manager = openManager(storePath, type);
    CertificateWithPrivateKey ed25519 = CertificateUtils.generateEd25519Identity(SUBJECT, VALIDITY);
    CertificateWithPrivateKey rsa = CertificateUtils.generateSelfSignedCertificateSecret("maps.example");
    manager.addPrivateKey("ed25519", ENTRY_PASSWORD, ed25519.getPrivateKey(), new Certificate[] {ed25519.getCertificate()});
    manager.addPrivateKey("rsa", ENTRY_PASSWORD, rsa.getPrivateKey(), new Certificate[] {rsa.getCertificate()});
    CertificateManager reloaded = openManager(storePath, type);
    verifyChallenge(reloaded.getKey("ed25519", ENTRY_PASSWORD), reloaded.getCertificate("ed25519").getPublicKey());
    assertEquals("RSA", reloaded.getKey("rsa", ENTRY_PASSWORD).getAlgorithm());
    assertEquals("RSA", reloaded.getCertificate("rsa").getPublicKey().getAlgorithm());
    if (type.equals("JKS")) {
      assertThrows(KeyStoreException.class, () -> new Ed25519IdentityManager(reloaded).createIdentity("new", ENTRY_PASSWORD, SUBJECT, VALIDITY));
      new Ed25519IdentityManager(reloaded).importTrustedCertificate("peer", ed25519.getCertificate().getEncoded());
      assertEquals(ed25519.getCertificate(), openManager(storePath, type).getCertificate("peer"));
    }
  }

  @Test
  void preservesExistingRsaCertificateGeneration() throws Exception {
    CertificateWithPrivateKey identity = CertificateUtils.generateSelfSignedCertificateSecret("maps.example");
    X509Certificate certificate = (X509Certificate) identity.getCertificate();
    certificate.verify(certificate.getPublicKey());
    assertEquals("RSA", identity.getPrivateKey().getAlgorithm());
    assertEquals("SHA256withRSA", certificate.getSigAlgName());
    assertEquals(Duration.ofDays(365).toMillis(), certificate.getNotAfter().getTime() - certificate.getNotBefore().getTime());
    assertTrue(certificate.getKeyUsage()[2]);
    assertTrue(certificate.getSubjectAlternativeNames().stream().anyMatch(name -> name.contains("maps.example")));
  }

  @Test
  void loadsIdentityProvisionedWithJdkKeytool() throws Exception {
    Path storePath = temporaryDirectory.resolve("keytool.p12");
    Path outputPath = temporaryDirectory.resolve("keytool.log");
    Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
        "-genkeypair", "-alias", "server", "-keyalg", "Ed25519", "-dname", "CN=maps-server", "-validity", "30",
        "-storetype", "PKCS12", "-keystore", storePath.toString(), "-storepass", "store-password", "-keypass", "store-password")
        .redirectErrorStream(true).redirectOutput(outputPath.toFile()).start();
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS), "keytool did not exit");
      assertEquals(0, process.exitValue(), Files.readString(outputPath));
    } finally {
      process.destroyForcibly();
    }
    CertificateManager manager = openManager(storePath, "PKCS12");
    verifyChallenge(manager.getKey("server", "store-password".toCharArray()), manager.getCertificate("server").getPublicKey());
  }

  static CertificateManager openManager(Path storePath, String type) throws Exception {
    return CertificateManagerFactory.getInstance().getManager(new ConfigurationProperties(
        Map.of("type", type, "path", storePath.toString(), "passphrase", "store-password")));
  }

  static void verifyChallenge(PrivateKey privateKey, PublicKey publicKey) throws Exception {
    byte[] challenge = "MapsMessaging transport identity challenge".getBytes(StandardCharsets.UTF_8);
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(privateKey);
    signer.update(challenge);
    byte[] signature = signer.sign();
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(publicKey);
    verifier.update(challenge);
    assertTrue(verifier.verify(signature));
    verifier.update("different challenge".getBytes(StandardCharsets.UTF_8));
    assertFalse(verifier.verify(signature));
  }

  private static Certificate certificateFor(KeyPair keyPair) throws Exception {
    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(SUBJECT, BigInteger.ONE,
        new Date(0), new Date(1000), SUBJECT, keyPair.getPublic());
    byte[] encoded = builder.build(new JcaContentSignerBuilder("Ed448").build(keyPair.getPrivate())).getEncoded();
    return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
  }

  private static final class RuntimeFailingSaveManager extends KeyStoreManager {

    private final RuntimeException failure = new IllegalStateException("Storage failed");

    private RuntimeFailingSaveManager(ConfigurationProperties configuration)
        throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
      super(configuration);
    }

    @Override
    public void saveKeyStore() {
      throw failure;
    }
  }
}
