package io.mapsmessaging.sasl.impl.htpasswd.hash;

public interface PasswordHash {

  char[] hash(String password);

}
