/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.sasl.provider.scram.msgs;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.StringTokenizer;
import lombok.Getter;
import lombok.Setter;

public class ChallengeResponse {

  private static final String[] FORCED_ORDER = new String[] {"c", "v", "r", "s", "i"};
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
  @Setter
  @Getter
  private String gs2Header = "";

  @Getter private String originalRequest;

  public ChallengeResponse() {
    data = new LinkedHashMap<>();
    originalRequest = "";
  }

  public ChallengeResponse(byte[] comms) throws IOException {
    this(new String(comms));
  }

  public ChallengeResponse(String comms) throws IOException {
    this();
    originalRequest = comms;
    parseString(comms);
  }

  public String get(String key) {
    return data.get(key);
  }

  public String remove(String key) {
    return data.remove(key);
  }

  public void put(String key, String value) {
    data.put(key, value);
  }

  private void parseString(String val) throws IOException {
    if (val.startsWith("y,") ||
        val.startsWith("p,")) {
      throw new IOException("GS2 Channel bonding not supported");
    }

    if (val.startsWith("n,")) {
      val = val.substring(2);
    }

    StringTokenizer st = new StringTokenizer(val, ",");
    while (st.hasMoreElements()) {
      String entry = st.nextElement().toString().trim();
      if (!entry.isEmpty()) {
        parseKeyValue(entry);
      }
    }
  }

  private void parseKeyValue(String keyValue) {
    int index = keyValue.indexOf("=");
    if (index > 0) {
      String key = keyValue.substring(0, index).trim();
      String val = keyValue.substring(index + 1).trim();
      data.put(key, val);
    }
  }

  public String toString() {
    StringBuilder stringBuilder = new StringBuilder();
    Map<String, String> tmpMap = new LinkedHashMap<>(data);
    for (String s : FORCED_ORDER) {
      if (tmpMap.containsKey(s)) {
        stringBuilder.append(s).append("=").append(tmpMap.get(s)).append(",");
        tmpMap.remove(s);
      }
    }

    for (Entry<String, String> entry : tmpMap.entrySet()) {
      stringBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append(",");
    }
    String result = gs2Header + stringBuilder;
    if (result.endsWith(",")) {
      result = result.substring(0, result.length() - 1);
    }
    originalRequest = result;
    return result;
  }

  public boolean isEmpty() {
    return data.isEmpty();
  }
}
