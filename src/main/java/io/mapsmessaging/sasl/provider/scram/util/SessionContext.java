package io.mapsmessaging.sasl.provider.scram.util;

import io.mapsmessaging.sasl.provider.scram.State;
import lombok.Getter;
import lombok.Setter;

public class SessionContext {

  @Getter
  @Setter
  private String clientNonce;

  @Getter
  @Setter
  private String serverNonce;

  @Getter
  @Setter
  private String passwordSalt;

  @Getter
  @Setter
  private String username;

  @Getter
  @Setter
  private State state;

  @Getter
  @Setter
  private int interations;

  public SessionContext(){}
}
