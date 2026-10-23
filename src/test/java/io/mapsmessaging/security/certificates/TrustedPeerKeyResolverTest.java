/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 * Licensed under the Apache License, Version 2.0 with the Commons Clause.
 */
package io.mapsmessaging.security.certificates;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustedPeerKeyResolverTest {

  @TempDir
  Path temporaryDirectory;

  private CertificateManager manager;
  private CertificateWithPrivateKey current;
  private CertificateWithPrivateKey next;
  private CertificateWithPrivateKey other;

  @BeforeEach
  void setUp() throws Exception {
    manager = Ed25519IdentityTest.openManager(temporaryDirectory.resolve("peers.p12"), "PKCS12");
    current = identity();
    next = identity();
    other = identity();
    Ed25519IdentityManager importer = new Ed25519IdentityManager(manager);
    importer.importTrustedCertificate("peer-current", current.getCertificate().getEncoded());
    importer.importTrustedCertificate("peer-next", next.getCertificate().getEncoded());
    importer.importTrustedCertificate("other", other.getCertificate().getEncoded());
  }

  @Test
  void resolvesExplicitlyConfiguredAliasesAndLogicalPeers() throws Exception {
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, Map.of("peer-current", List.of("peer-current")));
    assertEquals(current.getCertificate().getPublicKey(), resolver.getTrustedKey("peer-current"));
    assertEquals(List.of(current.getCertificate().getPublicKey()), resolver.getTrustedKeys("peer-current"));
    assertTrue(resolver.isTrusted("peer-current", current.getCertificate().getPublicKey()));
    assertFalse(resolver.isTrusted("peer-current", other.getCertificate().getPublicKey()));
  }

  @Test
  void rejectsUnknownAliasesAndStoredButUnauthorisedCertificates() {
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, Map.of("peer", List.of("peer-current")));
    assertThrows(CertificateException.class, () -> resolver.getTrustedKey("missing"));
    assertThrows(CertificateException.class, () -> resolver.getTrustedKey("other"));
    assertThrows(CertificateException.class, () -> resolver.getTrustedKeys("other"));
    assertThrows(CertificateException.class, () -> resolver.isTrusted("other", other.getCertificate().getPublicKey()));
    TrustedPeerKeyResolver missing = new TrustedPeerKeyResolver(manager, Map.of("peer", List.of("missing")));
    assertThrows(CertificateException.class, () -> missing.getTrustedKeys("peer"));
  }

  @Test
  void allowsRotationOnlyWithinConfiguredLogicalPeer() throws Exception {
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager,
        Map.of("peer", List.of("peer-current", "peer-next"), "second-peer", List.of("other")));
    assertEquals(2, resolver.getTrustedKeys("peer").size());
    assertTrue(resolver.isTrusted("peer", current.getCertificate().getPublicKey()));
    assertTrue(resolver.isTrusted("peer", next.getCertificate().getPublicKey()));
    assertFalse(resolver.isTrusted("peer", other.getCertificate().getPublicKey()));
    assertTrue(resolver.isTrusted("second-peer", other.getCertificate().getPublicKey()));
    assertFalse(resolver.isTrusted("second-peer", current.getCertificate().getPublicKey()));
    TrustedPeerKeyResolver rotated = new TrustedPeerKeyResolver(manager, Map.of("peer", List.of("peer-next")));
    assertFalse(rotated.isTrusted("peer", current.getCertificate().getPublicKey()));
    assertTrue(rotated.isTrusted("peer", next.getCertificate().getPublicKey()));
  }

  @Test
  void doesNotCacheKeysAfterCertificateRemoval() throws Exception {
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, Map.of("peer", List.of("peer-current")));
    assertTrue(resolver.isTrusted("peer", current.getCertificate().getPublicKey()));
    manager.deleteCertificate("peer-current");
    assertThrows(CertificateException.class, () -> resolver.getTrustedKeys("peer"));
  }

  @Test
  void pinsExplicitPublicKeysWithoutConflatingCertificateExpiryWithTrust() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    X500Principal subject = new X500Principal("CN=expired-pin-container");
    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
        new Date(0), new Date(1000), subject, keyPair.getPublic());
    byte[] encoded = builder.build(new JcaContentSignerBuilder("Ed25519").build(keyPair.getPrivate())).getEncoded();
    Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));
    assertThrows(CertificateExpiredException.class, () -> ((X509Certificate) certificate).checkValidity());
    new Ed25519IdentityManager(manager).importTrustedCertificate("expired", encoded);
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, Map.of("peer", List.of("expired")));
    assertTrue(resolver.isTrusted("peer", keyPair.getPublic()));
    assertFalse(resolver.isTrusted("peer", current.getCertificate().getPublicKey()));
  }

  @Test
  void rejectsUnexpectedAlgorithmsInConfiguredCertificatesAndPresentedKeys() throws Exception {
    CertificateWithPrivateKey rsa = CertificateUtils.generateSelfSignedCertificateSecret("maps.example");
    manager.addCertificate("rsa", rsa.getCertificate());
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, Map.of("peer", List.of("peer-current"), "rsa", List.of("rsa")));
    assertThrows(CertificateException.class, () -> resolver.getTrustedKey("rsa"));
    assertThrows(CertificateException.class, () -> resolver.isTrusted("peer", rsa.getCertificate().getPublicKey()));
  }

  @Test
  void copiesConfigurationAndReturnsImmutableKeyLists() throws Exception {
    List<String> aliases = new ArrayList<>(List.of("peer-current"));
    Map<String, List<String>> configuration = new HashMap<>();
    configuration.put("peer", aliases);
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, configuration);
    aliases.add("other");
    configuration.put("untrusted", List.of("other"));
    List<PublicKey> keys = resolver.getTrustedKeys("peer");
    assertEquals(1, keys.size());
    assertThrows(UnsupportedOperationException.class, () -> keys.add(other.getCertificate().getPublicKey()));
    assertThrows(CertificateException.class, () -> resolver.getTrustedKeys("untrusted"));
  }

  @Test
  void rejectsInvalidAllowListEntriesAndSupportsEmptyTrust() {
    assertThrows(IllegalArgumentException.class, () -> new TrustedPeerKeyResolver(manager, Map.of(" ", List.of("peer-current"))));
    assertThrows(IllegalArgumentException.class, () -> new TrustedPeerKeyResolver(manager, Map.of("peer", List.of(" "))));
    assertThrows(IllegalArgumentException.class, () -> new TrustedPeerKeyResolver(manager, Map.of("peer", List.of())));
    TrustedPeerKeyResolver resolver = new TrustedPeerKeyResolver(manager, Map.of());
    assertThrows(CertificateException.class, () -> resolver.getTrustedKeys("peer"));
  }

  private static CertificateWithPrivateKey identity() throws Exception {
    return CertificateUtils.generateEd25519Identity(new X500Principal("CN=same-name-does-not-grant-trust"), Duration.ofDays(30));
  }
}
