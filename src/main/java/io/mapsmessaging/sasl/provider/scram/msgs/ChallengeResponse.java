package io.mapsmessaging.sasl.provider.scram.msgs;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.StringTokenizer;

public class ChallengeResponse {

  public static final String USERNAME = "n";
  public static final String NONCE = "r";
  public static final String SALT = "s";
  public static final String VERIFIER = "v";
  public static final String PROOF = "p";
  public static final String ITERATION_COUNT = "i";
  public static final String GS2_CBIND_FLAG = "g";
  public static final String AUTHZID = "a";
  public static final String RESERVED = "m";
  public static final String CHANNEL_BINDING = "c";
  public static final String SERVER_ERROR = "e";


  private final Map<String, String> data;

  protected ChallengeResponse(){
    data = new LinkedHashMap<>();
  }

  public ChallengeResponse(byte[] comms){
    this(new String(comms));
  }

  public ChallengeResponse(String comms){
    this();
    parseString(comms);
  }

  public String get(String key){
    return data.get(key);
  }

  public byte[] getDecodedBase64(String key){
    String t = data.get(key);
    if(t != null){
      return Base64.getDecoder().decode(t);
    }
    return null;
  }

  public boolean contains(String key){
    return data.containsKey(key);
  }

  public void put(String key, String value){
    data.put(key, value);
  }

  public void putAsBase64Encoded(String key, byte[] value){
    data.put(key, Base64.getEncoder().encodeToString(value));
  }

  private void parseString(String val){
    StringTokenizer st = new StringTokenizer(val, ",");
    while(st.hasMoreElements()){
      parseKeyValue(((String) st.nextElement()).trim());
    }
  }

  private void parseKeyValue(String keyValue){
    int index = keyValue.indexOf("=");
    if(index > 0){
      String key = keyValue.substring(0, index).trim();
      String val = keyValue.substring(index+1).trim();
      data.put(key, val);
    }
  }

  public String toString(){
    StringBuilder stringBuilder = new StringBuilder();
    for(Entry<String, String> entry:data.entrySet()){
      stringBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append(",");
    }
    String result = stringBuilder.toString();
    return result.substring(0, result.length() -1);
  }

}
