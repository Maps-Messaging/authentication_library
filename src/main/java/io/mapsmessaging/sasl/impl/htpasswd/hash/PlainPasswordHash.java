package io.mapsmessaging.sasl.impl.htpasswd.hash;

public class PlainPasswordHash implements PasswordHash{

  @Override
  public char[] hash(String password, String salt) {
    return password.toCharArray();
  }
}
