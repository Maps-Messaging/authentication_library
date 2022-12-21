package io.mapsmessaging.sasl.impl.htpasswd.hash;

public interface PasswordHash {

  default char[] hash(String password){
    return hash(password, null);
  }

  char[] hash(String password, String salt);

}
