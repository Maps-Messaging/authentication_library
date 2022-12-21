package io.mapsmessaging.sasl.impl.htpasswd.hash;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Result;
import org.apache.nifi.security.util.crypto.BcryptSecureHasher;

public class BCryptPasswordHash implements PasswordHash {

  @Override
  public char[] hash(String password, String salt) {
    Result result = BCrypt.verifyer().verify(password.getBytes(), salt.getBytes());
    BcryptSecureHasher hasher = new BcryptSecureHasher();
    return hasher.hashBase64(password, salt).toCharArray();
  }
}
