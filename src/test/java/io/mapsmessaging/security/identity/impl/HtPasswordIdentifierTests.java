package io.mapsmessaging.security.identity.impl;

import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.htpasswd.HtPasswd;
import io.mapsmessaging.security.identity.parsers.Md5PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class HtPasswordIdentifierTests {

  @Test
  void simpleLoad() throws NoSuchUserFoundException {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("htPasswordFile", "./src/test/resources/.htpassword");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("htpassword", map);
    Assertions.assertEquals(lookup.getClass(), HtPasswd.class);
    char[] hash = lookup.getPasswordHash("test");
    Assertions.assertNotNull(hash);
    Assertions.assertNotEquals(0, hash.length);
    String pwd = new String(hash);
    Assertions.assertEquals("$apr1$9r.m87gj$5wXLLFhGKzknbwSLJj0HC1", pwd);
    PasswordParser passwordParser = PasswordParserFactory.getInstance().parse(pwd);
    Assertions.assertEquals(Md5PasswordParser.class, passwordParser.getClass());
  }

  @Test
  void noUser() {
    Map<String, String> map = new LinkedHashMap<>();
    map.put("htPasswordFile", "./src/test/resources/.htpassword");
    IdentityLookup lookup = IdentityLookupFactory.getInstance().get("htpassword", map);
    Assertions.assertEquals(lookup.getClass(), HtPasswd.class);
    Assertions.assertThrowsExactly(NoSuchUserFoundException.class, () -> lookup.getPasswordHash("noSuchUser"));
  }
}
