package io.mapsmessaging.sasl.provider.scram;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.StringTokenizer;

public class ChallengeResponse {

  private final Map<String, String> data;

  public ChallengeResponse(){
    data = new LinkedHashMap<>();
  }

  public ChallengeResponse(String comms){
    this();
    parseString(comms);
  }

  public String get(String key){
    return data.get(key);
  }

  public boolean contains(String key){
    return data.containsKey(key);
  }

  public void put(String key, String value){
    data.put(key, value);
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
