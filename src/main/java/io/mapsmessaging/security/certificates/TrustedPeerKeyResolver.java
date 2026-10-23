/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 * Licensed under the Apache License, Version 2.0 with the Commons Clause.
 */
package io.mapsmessaging.security.certificates;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Resolves explicit peer-key pins, independent of certificate validity and CA/chain validation.
 * Configuration is copied; certificates are read on every lookup so removed entries cannot remain cached.
 * The caller owns the certificate manager and must coordinate mutations on that manager's monitor.
 * A successful pin match does not prove possession: the consumer must verify the peer's signature.
 */
public final class TrustedPeerKeyResolver {

  private final CertificateManager certificateManager;
  private final Map<String, List<String>> peerAliases;
  private final Set<String> authorisedAliases;

  /** Maps each logical peer to one or more explicitly authorised certificate aliases, including rotation keys. */
  public TrustedPeerKeyResolver(CertificateManager certificateManager, Map<String, ? extends Collection<String>> peerAliases) {
    this.certificateManager = Objects.requireNonNull(certificateManager, "certificateManager");
    Objects.requireNonNull(peerAliases, "peerAliases");
    Map<String, List<String>> peers = new HashMap<>();
    Set<String> aliases = new HashSet<>();
    for (Map.Entry<String, ? extends Collection<String>> peer : peerAliases.entrySet()) {
      requireName(peer.getKey());
      List<String> configuredAliases = List.copyOf(peer.getValue());
      if (configuredAliases.isEmpty()) {
        throw new IllegalArgumentException("A configured peer must have at least one certificate alias");
      }
      for (String alias : configuredAliases) {
        requireName(alias);
        aliases.add(alias);
      }
      peers.put(peer.getKey(), configuredAliases);
    }
    this.peerAliases = Map.copyOf(peers);
    authorisedAliases = Set.copyOf(aliases);
  }

  /** Resolves only aliases present in the explicit configuration, not every certificate in the store. */
  public PublicKey getTrustedKey(String alias) throws CertificateException {
    synchronized (certificateManager) {
      if (alias == null || !authorisedAliases.contains(alias)) {
        throw new CertificateException("Unauthorised peer certificate alias: " + alias);
      }
      return CertificateUtils.ed25519PublicKey(certificateManager.getCertificate(alias));
    }
  }

  /** Fails closed if the logical peer is unknown or any of its configured certificates is missing/invalid. */
  public List<PublicKey> getTrustedKeys(String peer) throws CertificateException {
    synchronized (certificateManager) {
      List<String> aliases = peer == null ? null : peerAliases.get(peer);
      if (aliases == null) {
        throw new CertificateException("Unknown peer: " + peer);
      }
      List<PublicKey> publicKeys = new ArrayList<>();
      for (String alias : aliases) {
        publicKeys.add(getTrustedKey(alias));
      }
      return List.copyOf(publicKeys);
    }
  }

  /** Compares public-key encodings against this logical peer's pins; never imports a presented key. */
  public boolean isTrusted(String peer, PublicKey presentedKey) throws CertificateException {
    CertificateUtils.requireEd25519PublicKey(presentedKey);
    for (PublicKey trustedKey : getTrustedKeys(peer)) {
      if (MessageDigest.isEqual(trustedKey.getEncoded(), presentedKey.getEncoded())) {
        return true;
      }
    }
    return false;
  }

  private static void requireName(String name) {
    if (name == null || name.isBlank()) {
      throw new IllegalArgumentException("Peer names and certificate aliases must not be blank");
    }
  }
}
