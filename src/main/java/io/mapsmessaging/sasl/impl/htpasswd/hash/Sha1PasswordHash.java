package io.mapsmessaging.sasl.impl.htpasswd.hash;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class Sha1PasswordHash implements PasswordHash{

  @Override
  public char[] hash(String password, String salt) {
    String passwd64 = Base64.encodeBase64String(DigestUtils.sha1(password));
    return passwd64.toCharArray();
  }
}
