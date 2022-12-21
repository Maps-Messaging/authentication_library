package io.mapsmessaging.sasl;

public interface IdentityLookup {

  char[] getPasswordHash(String username) throws NoSuchUserFoundException;

}
