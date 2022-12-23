package io.mapsmessaging.sasl.provider.scram.msgs;

public class FirstClientMessage extends ChallengeResponse {

  public FirstClientMessage(byte[] msg){
    super(msg);
  }

  public FirstClientMessage(String msg){
    super(msg);
  }

  public FirstClientMessage() {
    super();
  }

  public boolean isValid() {
    return (!contains(USERNAME) || !contains(NONCE));
  }
}
