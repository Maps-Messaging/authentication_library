package io.mapsmessaging.security.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;

public class CryptoHelper {

  private CryptoHelper() {
    // This is a helper class and does not have any instance methods
  }

  public static MessageDigest findDigest(String algorithm) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = null;
    try {
      messageDigest = MessageDigest.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      int idx = algorithm.indexOf("-");
      if (idx > 0) {
        algorithm = algorithm.substring(0, idx) + algorithm.substring(idx + 1);
      }
      messageDigest = MessageDigest.getInstance(algorithm);
    }
    return messageDigest;
  }

  public static Mac findMac(String algorithm) {
    String macLookup = "Hmac" + algorithm.toUpperCase().trim();
    Mac mac;
    mac = attemptLookup(macLookup);
    if (mac == null) {
      int idx = macLookup.indexOf("-");
      if (idx > 0) {
        macLookup = macLookup.substring(0, idx) + macLookup.substring(idx + 1);
        mac = attemptLookup(macLookup);
      }
    }
    return mac;
  }

  private static Mac attemptLookup(String algorithm) {
    try {
      return Mac.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }


}
