package io.mapsmessaging.security.jaas;

import java.util.LinkedHashMap;
import java.util.Map;

class HtPasswordLoginTest extends BaseIdentity {

  Map<String, String> getOptions() {
    Map<String, String> options = new LinkedHashMap<>();
    options.put("identityName", "htpassword");
    options.put("passwordFile", "./src/test/resources/.htpassword");
    return options;
  }

  @Override
  String getUser() {
    return "test2";
  }

  @Override
  String getPassword() {
    return "This is an md5 password";
  }
}
