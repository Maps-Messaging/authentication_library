package io.mapsmessaging.sasl.impl.htpasswd;

import lombok.Getter;

public enum HashType {
  PLAIN(""),
  MD5("$apr1$"),
  SHA1("{SHA}"),
  BCRYPT("$2y$");

  @Getter
  private final String name;

  HashType(String name) {
    this.name = name;
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
