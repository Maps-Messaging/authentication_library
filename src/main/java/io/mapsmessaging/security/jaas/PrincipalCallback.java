package io.mapsmessaging.security.jaas;

import javax.security.auth.callback.Callback;
import java.security.Principal;

public class PrincipalCallback implements Callback {

  private Principal principal;

  public Principal getPrincipal() {
    return principal;
  }

  public void setPrincipal(Principal principal) {
    this.principal = principal;
  }
}
