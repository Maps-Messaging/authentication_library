/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.AccessDecision;
import io.mapsmessaging.security.authorisation.Grantee;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.ProtectedResource;
import io.mapsmessaging.security.authorisation.ResourceCreationContext;
import io.mapsmessaging.security.authorisation.ResourceInitialGrantPolicy;
import io.mapsmessaging.security.authorisation.ResourceTraversal;
import io.mapsmessaging.security.authorisation.ResourceTraversalFactory;
import io.mapsmessaging.security.authorisation.impl.acl.AclAuthorizationProvider;
import io.mapsmessaging.security.authorisation.impl.acl.AclLoadState;
import io.mapsmessaging.security.authorisation.impl.acl.AclSaveState;
import io.mapsmessaging.security.authorisation.impl.caching.CachingAuthorizationProvider;
import io.mapsmessaging.security.identity.GroupEntry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Local ACL demonstration: application permissions, group inheritance, explicit deny, revoke and encrypted state reload. */
public final class AuthorizationExample {
  private AuthorizationExample() {}

  public static void main(String[] arguments) throws IOException, GeneralSecurityException {
    Path directory = Files.createTempDirectory("authorization-example-");
    Path stateFile = directory.resolve("acl-state.dat");
    try {
      KeyGenerator generator = KeyGenerator.getInstance("AES");
      generator.init(256);
      SecretKey key = generator.generateKey();
      AclSaveState saveState = new AclSaveState(stateFile.toString(), key);
      ResourceTraversalFactory traversalFactory = new SlashTraversalFactory();
      AclAuthorizationProvider acl = new AclAuthorizationProvider("", DemoPermission.values(), saveState, traversalFactory);
      CachingAuthorizationProvider provider = new CachingAuthorizationProvider(acl, Duration.ofSeconds(5));
      try {
        // Fixed IDs make this demo reproducible. Real integrations obtain stable UUIDs from identity/group mappings.
        Group operators = new Group(UUID.fromString("00000000-0000-0000-0000-000000000001"), new GroupEntry("operators", Set.of("alice")));
        Identity alice = new Identity(UUID.fromString("00000000-0000-0000-0000-000000000002"), "alice", Map.of(), List.of(operators));
        ProtectedResource parent = new ProtectedResource("topic", "fleet/site", "demo");
        ProtectedResource child = new ProtectedResource("topic", "fleet/site/telemetry", "demo");

        provider.registerResource(child, new ResourceCreationContext(alice, parent, ResourceInitialGrantPolicy.OWNER_FULL));
        requireAccess(provider, alice, child, false, "ACL registration does not grant owner permissions");

        provider.grant(operators, DemoPermission.READ, parent);
        requireAccess(provider, alice, child, true, "Parent group grant is inherited through application traversal");

        provider.denyAccess(Grantee.forIdentity(alice), DemoPermission.READ, child);
        requireAccess(provider, alice, child, false, "Explicit child identity deny stops traversal");
        AccessDecision decision = provider.explainAccess(alice, DemoPermission.READ, child);
        System.out.println("Decision reason: " + decision.getDecisionReason());

        // Revoke removes the local allow/deny bit; the inherited parent grant becomes visible again.
        provider.revoke(alice, DemoPermission.READ, child);
        requireAccess(provider, alice, child, true, "Revocation restores inherited access");

        ProtectedResource otherTenant = new ProtectedResource("topic", "fleet/site/telemetry", "other");
        requireAccess(provider, alice, otherTenant, false, "Traversal preserves tenant isolation");

        String savedState = new AclLoadState(stateFile.toString(), key).loadState();
        AclAuthorizationProvider reloaded = new AclAuthorizationProvider(savedState, DemoPermission.values(), saveState, traversalFactory);
        if (!reloaded.canAccess(alice, DemoPermission.READ, child)) {
          throw new IllegalStateException("Saved ACL state did not restore the parent grant");
        }
        System.out.println("Encrypted ACL state reloaded successfully");
      } finally {
        provider.shutdown();
      }
    } finally {
      Files.deleteIfExists(stateFile);
      Files.deleteIfExists(directory);
    }
  }

  private static void requireAccess(
      CachingAuthorizationProvider provider, Identity identity, ProtectedResource resource, boolean expected, String description) {
    boolean allowed = provider.canAccess(identity, DemoPermission.READ, resource);
    if (allowed != expected) {
      throw new IllegalStateException(description + ": expected " + expected + ", got " + allowed);
    }
    System.out.println(description + ": " + allowed);
  }

  public enum DemoPermission implements Permission {
    READ("read", "Read a topic", 1L),
    WRITE("write", "Write a topic", 2L);

    private final String name;
    private final String description;
    private final long mask;

    DemoPermission(String name, String description, long mask) {
      this.name = name;
      this.description = description;
      this.mask = mask;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public String getDescription() {
      return description;
    }

    @Override
    public long getMask() {
      return mask;
    }
  }

  private static final class SlashTraversalFactory implements ResourceTraversalFactory {
    @Override
    public ResourceTraversal create(ProtectedResource resource) {
      return new SlashTraversal(resource);
    }
  }

  /** This application's hierarchy includes the exact resource, every slash parent and the empty root. */
  private static final class SlashTraversal implements ResourceTraversal {
    private ProtectedResource current;

    private SlashTraversal(ProtectedResource resource) {
      current = resource;
    }

    @Override
    public ProtectedResource current() {
      return current;
    }

    @Override
    public boolean hasMore() {
      return current != null;
    }

    @Override
    public void moveToParent() {
      String resourceId = current.getResourceId();
      if (resourceId.isEmpty()) {
        current = null;
        return;
      }
      int slash = resourceId.lastIndexOf('/');
      String parentId = slash < 0 ? "" : resourceId.substring(0, slash);
      current = new ProtectedResource(current.getResourceType(), parentId, current.getTenant());
    }
  }
}
