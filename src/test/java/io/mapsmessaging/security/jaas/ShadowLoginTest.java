package io.mapsmessaging.security.jaas;

import java.util.LinkedHashMap;
import java.util.Map;

class ShadowLoginTest extends BaseIdentity {


  Map<String, String> getOptions() {
    Map<String, String> options = new LinkedHashMap<>();
    options.put("identityName", "shadow");
    options.put("passwordFile", "./src/test/resources/shadow");
    return options;
  }


  @Override
  String getUser() {
    return "test";
  }

  @Override
  String getPassword() {
    return "onewordpassword";
  }

}
