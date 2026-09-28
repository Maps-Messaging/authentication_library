/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.identity.impl.ldap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Test;

class LdapUserCoverageTest {

  private static final char[] PASSWORD =
      "$6$DVW4laGf$QwTuOOtd.1G3u2fs8d5/OtcQ73qTbwA.oAC1XWTmkkjrvDLEJ2WweTcBdxRkzfjQVfZCw3OVVBAMsIGMkH3On/"
          .toCharArray();

  @Test
  void extractsKnownAttributesAndBuildsPrincipals() {
    BasicAttributes attributes = new BasicAttributes(true);
    attributes.put(new BasicAttribute("homeDirectory", "/home/alice"));
    attributes.put(new BasicAttribute("gecos", "Alice Example"));
    attributes.put(new BasicAttribute("cn", "alice"));
    attributes.put(new BasicAttribute("mail", "alice@example.com"));
    attributes.put(new BasicAttribute("userPassword", "hidden"));

    LdapUser user = new LdapUser("alice", PASSWORD, attributes);

    assertEquals("/home/alice", user.getHomeDirectory());
    assertEquals("Alice Example", user.getDescription());

    Subject subject = user.getSubject();
    Set<String> principalNames =
        subject.getPrincipals().stream().map(Principal::getName).collect(Collectors.toSet());

    assertTrue(principalNames.contains("alice"));
    assertTrue(principalNames.contains("everyone"));
    assertTrue(principalNames.contains("/home/alice"));
    assertTrue(principalNames.contains("Alice Example"));
    assertTrue(principalNames.stream().anyMatch(name -> name.contains("mail")));
    assertTrue(principalNames.stream().noneMatch(name -> name.contains("userPassword")));
  }

  @Test
  void exportsLdapAttributesAndSupportsLdapGroup() {
    BasicAttributes attributes = new BasicAttributes(true);
    attributes.put(new BasicAttribute("homeDirectory", "/srv/alice"));
    attributes.put(new BasicAttribute("gecos", "Alice"));
    attributes.put(new BasicAttribute("uidNumber", "1001"));

    LdapUser user = new LdapUser("alice", PASSWORD, attributes);
    Map<String, String> map = new HashMap<>();

    user.setAttributeMap(map);

    assertEquals("homeDirectory: /srv/alice", map.get("homeDirectory"));
    assertEquals("Alice", map.get("description"));
    assertTrue(map.get("uidNumber").contains("1001"));

    LdapGroup group = new LdapGroup("operators");
    assertEquals("operators", group.getName());
    assertTrue(group.getUsers().isEmpty());
  }
}
