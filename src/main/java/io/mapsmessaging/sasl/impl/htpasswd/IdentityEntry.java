package io.mapsmessaging.sasl.impl.htpasswd;

import java.util.StringTokenizer;
import lombok.Getter;

public class IdentityEntry {

  @Getter
  private final String username;
  @Getter
  private final HashType hashType;
  @Getter
  private final char[] passwordHash;
  @Getter
  private final String salt;

  public IdentityEntry(String line) {
    int usernamePos = line.indexOf(":");
    username = line.substring(0, usernamePos);
    line = line.substring(usernamePos + 1);

    hashType = HashType.detect(line);
    line = line.substring(hashType.getName().length());
    switch (hashType) {
      case SHA1:
        salt = "";
        passwordHash = line.toCharArray();
        break;

      case MD5:
        StringTokenizer stringTokenizer = new StringTokenizer(line, "$");
        salt = stringTokenizer.nextElement().toString();
        passwordHash = stringTokenizer.nextElement().toString().toCharArray();
        break;

      case BCRYPT:
        stringTokenizer = new StringTokenizer(line, "$");
        salt = stringTokenizer.nextElement().toString();
        passwordHash = stringTokenizer.nextElement().toString().toCharArray();
        break;

      default:
        passwordHash = line.toCharArray();
        salt = "";
    }
  }

  @Override
  public String toString() {
    switch (hashType) {
      case MD5:
      case BCRYPT:
        return username + ":" + hashType.getName() + salt + "$" + new String(passwordHash) + "\n";

      case SHA1:
        return username + ":" + hashType.getName() + new String(passwordHash) + "\n";

      case PLAIN:
      default:
        return username + ":" + new String(passwordHash) + "\n";
    }
  }
}
