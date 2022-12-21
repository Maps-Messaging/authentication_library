package io.mapsmessaging.sasl.impl.htpasswd.hash;

import org.apache.commons.codec.digest.Md5Crypt;

public class MD5PasswordHash implements PasswordHash {

  @Override
  public char[] hash(String password, String salt) {
    return Md5Crypt.apr1Crypt(password.getBytes(), salt ).toCharArray();
  }
}
