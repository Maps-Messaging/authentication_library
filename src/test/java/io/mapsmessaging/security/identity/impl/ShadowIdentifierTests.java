package io.mapsmessaging.security.identity.impl;

import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.shadow.Shadow;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import io.mapsmessaging.security.identity.parsers.sha.Sha512PasswordParser;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ShadowIdentifierTests {

  @Test
  void simpleLoad() throws NoSuchUserFoundException {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("shadowFile", "./src/test/resources/shadow");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("shadow", map);
    Assertions.assertEquals(lookup.getClass(), Shadow.class);
    char[] hash = lookup.getPasswordHash("test");
    Assertions.assertNotNull(hash);
    Assertions.assertNotEquals(0, hash.length);
    String pwd = new String(hash);
    Assertions.assertEquals("$6$DVW4laGf$QwTuOOtd.1G3u2fs8d5/OtcQ73qTbwA.oAC1XWTmkkjrvDLEJ2WweTcBdxRkzfjQVfZCw3OVVBAMsIGMkH3On/", pwd);
    PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(pwd);
    Assertions.assertEquals(Sha512PasswordParser.class, passwordParser.getClass());
  }

  @Test
  void noUser() {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("shadowFile", "./src/test/resources/shadow");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("shadow", map);
    Assertions.assertEquals(lookup.getClass(), Shadow.class);
    Assertions.assertThrowsExactly(NoSuchUserFoundException.class, () -> lookup.getPasswordHash("noSuchUser"));
  }

}
