package io.mapsmessaging.sasl.impl.htpasswd.hash;

import org.apache.nifi.security.util.crypto.BcryptSecureHasher;

public class BCryptPasswordHash implements PasswordHash {

  @Override
  public char[] hash(String password, String salt) {
    BcryptSecureHasher hasher = new BcryptSecureHasher();
    return hasher.hashBase64(password, salt).toCharArray();
  }
}
