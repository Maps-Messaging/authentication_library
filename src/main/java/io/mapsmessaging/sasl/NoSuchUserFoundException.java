package io.mapsmessaging.sasl;

import java.io.IOException;

public class NoSuchUserFoundException extends IOException {

  public NoSuchUserFoundException(String s) {
    super(s);
  }
}
