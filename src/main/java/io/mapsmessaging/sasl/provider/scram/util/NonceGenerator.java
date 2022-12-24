package io.mapsmessaging.sasl.provider.scram.util;

import java.security.SecureRandom;

public class NonceGenerator {

  private static final byte[] NONCE_CHARS = "+abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes();

  private final SecureRandom prng;

  public NonceGenerator() {
    prng = new SecureRandom();
  }

  public String generateNonce(int size) {
    byte[] nonce = new byte[size];
    int x = 0;
    while(x<size){
      int idx = Math.abs(prng.nextInt(NONCE_CHARS.length));
      nonce[x] = NONCE_CHARS[idx];
      x++;
    }
    return new String(nonce);
  }

  public static void main(String[] args){
    for(int x=0;x<100;x++){
      NonceGenerator nonceGenerator = new NonceGenerator();
      System.err.println(nonceGenerator.generateNonce(48));
    }
  }
}
