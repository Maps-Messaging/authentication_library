/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 */

package io.mapsmessaging.security.sasl.provider.scram.msgs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;

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

  private final Map<String, String> data = new LinkedHashMap<>();

  @Getter private String gs2Header = "";
  @Getter private String originalRequest = "";

  public ChallengeResponse() {}

  public ChallengeResponse(byte[] comms) throws IOException {
    this(decodeUtf8(comms));
  }

  public ChallengeResponse(String comms) throws IOException {
    if (comms == null) {
      throw new IOException("SCRAM message must not be null");
    }
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
    if (!isAttributeName(key) || value == null || data.putIfAbsent(key, value) != null) {
      throw new IllegalArgumentException("Invalid or duplicate SCRAM attribute: " + key);
    }
  }

  public boolean contains(String key) {
    return data.containsKey(key);
  }

  public List<String> keys() {
    return List.copyOf(data.keySet());
  }

  public Map<String, String> values() {
    return Collections.unmodifiableMap(data);
  }

  public void setGs2Header(String gs2Header) {
    if (gs2Header == null || (!gs2Header.startsWith("n,") && !gs2Header.startsWith("y,")) || !gs2Header.endsWith(",")) {
      throw new IllegalArgumentException("Invalid GS2 header");
    }
    this.gs2Header = gs2Header;
  }

  public String getBareMessage() {
    return serializeAttributes();
  }

  private void parseString(String value) throws IOException {
    String attributes = value;
    if (value.startsWith("p=")) {
      throw new IOException("SCRAM channel binding is not supported");
    }
    if (value.startsWith("n,") || value.startsWith("y,")) {
      int secondComma = value.indexOf(',', 2);
      if (secondComma < 0) {
        throw new IOException("Invalid GS2 header");
      }
      gs2Header = value.substring(0, secondComma + 1);
      validateGs2Header(gs2Header);
      attributes = value.substring(secondComma + 1);
    }
    if (attributes.isEmpty()) {
      return;
    }
    String[] entries = attributes.split(",", -1);
    for (String entry : entries) {
      if (entry.isEmpty()) {
        throw new IOException("Empty SCRAM attribute");
      }
      parseKeyValue(entry);
    }
  }

  private void validateGs2Header(String header) throws IOException {
    String authzid = header.substring(2, header.length() - 1);
    if (!authzid.isEmpty() && (!authzid.startsWith("a=") || authzid.length() == 2)) {
      throw new IOException("Invalid GS2 authorization identity");
    }
  }

  private void parseKeyValue(String keyValue) throws IOException {
    int index = keyValue.indexOf('=');
    if (index != 1) {
      throw new IOException("Invalid SCRAM attribute");
    }
    String key = keyValue.substring(0, 1);
    if (!isAttributeName(key) || RESERVED.equals(key)) {
      throw new IOException("Unsupported SCRAM attribute: " + key);
    }
    if (data.putIfAbsent(key, keyValue.substring(2)) != null) {
      throw new IOException("Duplicate SCRAM attribute: " + key);
    }
  }

  private boolean isAttributeName(String key) {
    return key != null && key.length() == 1 && ((key.charAt(0) >= 'A' && key.charAt(0) <= 'Z') || (key.charAt(0) >= 'a' && key.charAt(0) <= 'z'));
  }

  private String serializeAttributes() {
    StringBuilder result = new StringBuilder();
    for (Map.Entry<String, String> entry : data.entrySet()) {
      if (!result.isEmpty()) {
        result.append(',');
      }
      result.append(entry.getKey()).append('=').append(entry.getValue());
    }
    return result.toString();
  }

  @Override
  public String toString() {
    originalRequest = gs2Header + serializeAttributes();
    return originalRequest;
  }

  public boolean isEmpty() {
    return data.isEmpty();
  }

  private static String decodeUtf8(byte[] value) throws IOException {
    try {
      return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString();
    } catch (CharacterCodingException e) {
      throw new IOException("SCRAM message is not valid UTF-8", e);
    }
  }
}
