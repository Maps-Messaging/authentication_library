/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 * Licensed under the Apache License, Version 2.0 with the Commons Clause.
 */
package io.mapsmessaging.security.certificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Collection;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * Explicit administrator provisioning through an existing certificate manager and its configured storage.
 * The caller owns the manager. Provisioning synchronizes on it; use one manager/writer per store and do not
 * mutate its keystore concurrently through other APIs. The storage implementation determines write durability.
 */
public final class Ed25519IdentityManager {

  private final CertificateManager certificateManager;

  public Ed25519IdentityManager(CertificateManager certificateManager) {
    this.certificateManager = Objects.requireNonNull(certificateManager, "certificateManager");
  }

  /** Generates and persists a new private-key entry. Existing entries of any kind are never replaced. */
  public CertificateWithPrivateKey createIdentity(String alias, char[] entryPassword, X500Principal subject, Duration validity)
      throws GeneralSecurityException, OperatorCreationException, IOException {
    synchronized (certificateManager) {
      if (!"PKCS12".equalsIgnoreCase(certificateManager.getKeyStore().getType())) {
        throw new KeyStoreException("Identity provisioning requires a PKCS12 keystore");
      }
      requireUnusedAlias(alias);
      if (entryPassword == null) {
        throw new KeyStoreException("An identity entry password is required");
      }
      CertificateWithPrivateKey identity = CertificateUtils.generateEd25519Identity(subject, validity);
      try {
        certificateManager.addPrivateKey(alias, entryPassword, identity.getPrivateKey(), new Certificate[] {identity.getCertificate()});
      } catch (CertificateException | RuntimeException failure) {
        removeUnpersistedEntry(alias, failure);
        throw failure;
      }
      return identity;
    }
  }

  /** Returns only the public X.509 certificate in DER format. No private-key encoding is accessed. */
  public byte[] exportCertificate(String alias) throws CertificateException {
    synchronized (certificateManager) {
      Certificate certificate = certificateManager.getCertificate(alias);
      CertificateUtils.ed25519PublicKey(certificate);
      return certificate.getEncoded();
    }
  }

  /**
   * Imports exactly one administrator-supplied X.509 certificate (DER or PEM) as a public-key pin container.
   * Certificate lifetime, subject and chain do not establish trust. Callers must authorise aliases separately.
   */
  public void importTrustedCertificate(String alias, byte[] encodedCertificate) throws GeneralSecurityException {
    synchronized (certificateManager) {
      requireUnusedAlias(alias);
      if (encodedCertificate == null) {
        throw new CertificateException("An encoded certificate is required");
      }
      Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
          .generateCertificates(new ByteArrayInputStream(encodedCertificate));
      if (certificates.size() != 1) {
        throw new CertificateException("Exactly one peer certificate is required");
      }
      Certificate certificate = certificates.iterator().next();
      CertificateUtils.ed25519PublicKey(certificate);
      try {
        certificateManager.addCertificate(alias, certificate);
      } catch (CertificateException | RuntimeException failure) {
        removeUnpersistedEntry(alias, failure);
        throw failure;
      }
    }
  }

  private void requireUnusedAlias(String alias) throws KeyStoreException {
    if (alias == null || alias.isBlank()) {
      throw new KeyStoreException("A non-blank alias is required");
    }
    if (certificateManager.getKeyStore().containsAlias(alias)) {
      throw new KeyStoreException("Alias already exists: " + alias);
    }
  }

  private void removeUnpersistedEntry(String alias, Exception failure) {
    try {
      certificateManager.getKeyStore().deleteEntry(alias);
    } catch (KeyStoreException cleanupFailure) {
      failure.addSuppressed(cleanupFailure);
    }
  }
}
