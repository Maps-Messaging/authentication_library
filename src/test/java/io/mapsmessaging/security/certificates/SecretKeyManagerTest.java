/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 * Licensed under the Apache License, Version 2.0 with the Commons Clause.
 */
package io.mapsmessaging.security.certificates;

import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class SecretKeyManagerTest extends BaseCertificateTest {
  private static final char[] PASSWORD = "entry-secret".toCharArray();
  private static final SecretKey AES = new SecretKeySpec(new byte[32], "AES");

  @Test void goodJceksRoundTripReopenAndDelete() throws Exception {
    setUp("JCEKS", "file");
    SecretKeyManager writer = (SecretKeyManager) certificateManager;
    writer.addSecretKey("sensor-1", PASSWORD, AES);
    assertArrayEquals(AES.getEncoded(), writer.getSecretKey("sensor-1", PASSWORD).getEncoded());
    SecretKeyManager reader = (SecretKeyManager) createManager("JCEKS", "file");
    assertArrayEquals(AES.getEncoded(), reader.getSecretKey("sensor-1", PASSWORD).getEncoded());
    reader.deleteSecretKey("sensor-1");
    SecretKeyManager reopened = (SecretKeyManager) createManager("JCEKS", "file");
    assertThrows(GeneralSecurityException.class, () -> reopened.getSecretKey("sensor-1", PASSWORD));
  }

  @Test void goodPkcs12WhenSupportedByJavaProvider() throws Exception {
    setUp("PKCS12", "file");
    SecretKeyManager manager = (SecretKeyManager) certificateManager;
    // SunPKCS12 supports symmetric SecretKeyEntry; tests provider-dependent behaviour.
    manager.addSecretKey("hmac-key", KEY_PASSWORD, new SecretKeySpec(new byte[32], "HmacSHA256"));
    assertEquals("HmacSHA256", manager.getSecretKey("hmac-key", KEY_PASSWORD).getAlgorithm());
  }

  @Test void badAliasAndMissingEntries() throws Exception {
    setUp("JCEKS", "file");
    SecretKeyManager manager = (SecretKeyManager) certificateManager;
    assertThrows(KeyStoreException.class, () -> manager.addSecretKey("", PASSWORD, AES));
    assertThrows(GeneralSecurityException.class, () -> manager.getSecretKey("missing", PASSWORD));
    assertThrows(GeneralSecurityException.class, () -> manager.deleteSecretKey("missing"));
  }

  @Test void badDuplicateAndWrongPassword() throws Exception {
    setUp("JCEKS", "file");
    SecretKeyManager manager = (SecretKeyManager) certificateManager;
    manager.addSecretKey("key", PASSWORD, AES);
    assertThrows(KeyStoreException.class, () -> manager.addSecretKey("key", PASSWORD, AES));
    assertThrows(GeneralSecurityException.class, () -> manager.getSecretKey("key", "wrong".toCharArray()));
    assertThrows(KeyStoreException.class, () -> manager.getSecretKey("key", null));
  }

  @Test void murphyJksRejectsSecretEntriesWithoutCorruptingCertificateStore() throws Exception {
    setUp("JKS", "file");
    SecretKeyManager manager = (SecretKeyManager) certificateManager;
    assertThrows(GeneralSecurityException.class, () -> manager.addSecretKey("key", PASSWORD, AES));
    assertTrue(certificateManager.getAliases().isEmpty());
  }

  @Test void murphyNoDeletingPrivateOrCertificateEntriesViaSecretApi() throws Exception {
    setUp("JCEKS", "file");
    addCert(certificateManager);
    SecretKeyManager manager = (SecretKeyManager) certificateManager;
    assertThrows(KeyStoreException.class, () -> manager.deleteSecretKey(TEST_ALIAS));
    assertNotNull(certificateManager.getKey(TEST_ALIAS, KEY_PASSWORD));
  }

  @Test void murphyNullKeyAndPasswordRejected() throws Exception {
    setUp("JCEKS", "file");
    SecretKeyManager manager = (SecretKeyManager) certificateManager;
    assertThrows(KeyStoreException.class, () -> manager.addSecretKey("null", PASSWORD, null));
    assertThrows(KeyStoreException.class, () -> manager.addSecretKey("missing-pass", null, AES));
  }
}
