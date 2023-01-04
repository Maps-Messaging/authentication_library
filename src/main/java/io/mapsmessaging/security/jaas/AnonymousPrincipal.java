package io.mapsmessaging.security.jaas;

import java.security.Principal;

public class AnonymousPrincipal  implements Principal {

  private final String name;

  public AnonymousPrincipal(String name) {
    this.name = name;
  }

  @Override
  public String getName() {
    return name;
  }
}
