/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 * Licensed under the Apache License, Version 2.0 with the Commons Clause.
 */
package io.mapsmessaging.security.certificates;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;

/**
 * Optional keystore capability for symmetric encryption and MAC keys.
 * CertificateManager.getKey continues to return only PrivateKey.
 */
public interface SecretKeyManager {
  SecretKey getSecretKey(String alias, char[] entryPassword) throws GeneralSecurityException;
  void addSecretKey(String alias, char[] entryPassword, SecretKey key) throws GeneralSecurityException;
  void deleteSecretKey(String alias) throws GeneralSecurityException;
}
