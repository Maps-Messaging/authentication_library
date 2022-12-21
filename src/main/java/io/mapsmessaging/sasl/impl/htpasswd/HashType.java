package io.mapsmessaging.sasl.impl.htpasswd;

import io.mapsmessaging.sasl.impl.htpasswd.hash.MD5PasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.PasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.PlainPasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.Sha1PasswordHash;
import lombok.Getter;

public enum HashType {
  PLAIN("", new PlainPasswordHash()),
  MD5("$apr1$", new MD5PasswordHash()),
  SHA1("{SHA}", new Sha1PasswordHash()),
  BCRYPT("$2y$", new Sha1PasswordHash());

  @Getter
  private final String name;

  @Getter
  private final PasswordHash passwordHash;

  HashType(String name, PasswordHash passwordHash) {
    this.name = name;
    this.passwordHash = passwordHash;
  }

  public static HashType detect(String type) {
    String test = type.toLowerCase();
    if (test.startsWith("$apr1$")) {
      return MD5;
    } else if (test.startsWith("{sha}")) {
      return SHA1;
    } else if (test.startsWith("$2y$")) {
      return BCRYPT;
    }
    return PLAIN;
  }
}
