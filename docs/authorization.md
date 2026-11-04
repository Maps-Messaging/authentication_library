# Authorization

Authorization checks an authenticated, mapped `Identity` against an application `Permission` and `ProtectedResource`. The API package is spelled `io.mapsmessaging.security.authorisation`; class names use `AuthorizationProvider`.

The complete [AuthorizationExample.java](../examples/java/AuthorizationExample.java) needs no external service. It defines a permission enum, a slash-separated resource traversal, stable demo identity/group UUIDs, an AES-encrypted temporary ACL state file and a cache wrapper. It checks inherited access, a child deny, revocation, tenant isolation and state reload. See [example build/run instructions](../examples/README.md).

## Integration contract

| Type | Application responsibility |
| --- | --- |
| `Identity` | Resolve after authentication using trusted, stable user UUID mappings and current mapped groups |
| `Permission` | Supply names, descriptions and masks for the application's operations |
| `ProtectedResource` | Supply consistent resource type, resource ID and optional tenant |
| `ResourceTraversalFactory` | Define the hierarchy the provider may examine for inherited decisions |
| `AuthorizationProvider` | Check access and apply policy/lifecycle updates through the selected implementation |

The permission interface has three methods: `getName()`, `getDescription()` and `getMask()`. For ACL use, allocate one distinct non-zero bit per permission, such as read `1L`, write `2L` and delete `4L`. Keep names and bit assignments stable across saved ACL state and deployments. There are 64 bits in the mask; shifts beyond that do not create additional unique bits.

Check individual permissions, or build `AuthRequest[]` and use `hasAllAccess`/`hasOneAccess`. The ACL/caching implementations iterate requests; for an empty array `hasAllAccess` returns true and `hasOneAccess` returns false. ACL evaluates a mask by intersection, so a composite mask is not an all-bits-required check. Use separate requests when all operations must be authorized.

Resource identity in ACL storage is the tuple `(resourceType, resourceId, tenant)`. The library does not canonicalize path strings or create application resources for you. Decide how to normalize paths, represent root and handle tenant names before granting policy. Use the same representation in checks, grants, deletion and traversal.

Sources: [AuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/AuthorizationProvider.java), [Permission](../src/main/java/io/mapsmessaging/security/authorisation/Permission.java), [ProtectedResource](../src/main/java/io/mapsmessaging/security/authorisation/ProtectedResource.java), [AuthRequest](../src/main/java/io/mapsmessaging/security/authorisation/AuthRequest.java), [ResourceKey](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/ResourceKey.java).

## Select a provider deliberately

`AuthorizationProviderFactory.get(name, config, permissions, traversalFactory)` creates a service-loaded provider. Names are matched case-insensitively. A null traversal factory uses `DefaultResourceTraversal`, which examines only the exact resource. An unknown provider name returns `null`; validate that result at startup.

| Provider name | Behavior and prerequisites |
| --- | --- |
| `ACL` | Local per-resource UUID/permission ACLs; factory creation requires certificate-store configuration and a writable state directory |
| `OpenFGA` | External relationship-based authorization; requires service/store/model configuration compatible with the application's permissions |
| `Open` | Always allows runtime checks; grant, deny and revoke operations are no-ops |
| `Caching` | Wrapper, not a selectable base provider; the factory explicitly excludes it as the base name |

If `IdentityAccessManager` has no `authorisationProvider` configuration entry, it uses `OpenAuthorizationProvider`. Authentication therefore does not imply a deny-by-default authorization policy. Select the desired provider explicitly.

Factory configuration uses a root `authorisation` object for cache settings. If that object exists, caching defaults to enabled and `cachingTime` defaults to 10 seconds. If it is absent, the factory does not wrap the provider. Set `authorisation.enableCaching=false` when an uncached provider is required. See [configuration](../Config.md) for complete setup.

Sources: [AuthorizationProviderFactory](../src/main/java/io/mapsmessaging/security/authorisation/AuthorizationProviderFactory.java), [IdentityAccessManager](../src/main/java/io/mapsmessaging/security/access/IdentityAccessManager.java), [OpenAuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/impl/open/OpenAuthorizationProvider.java).

## ACL decision order

ACL does not implement a global deny-overrides policy. It uses the first decisive result in the following order:

1. Start at the resource returned by `traversal.current()` while `hasMore()` is true.
2. Look for that identity UUID's ACL entry. An intersecting allow bit returns allow; otherwise an intersecting deny bit returns deny.
3. If the identity has no decision for this permission, inspect groups in the order of `Identity.getGroupList()`. The first group entry with an intersecting allow or deny decides.
4. If no entry at this resource decides, call `moveToParent()` and repeat.
5. If the traversal ends without a decision, deny.

Consequences:

| Policy arrangement | Result |
| --- | --- |
| Child has an explicit identity deny; parent allows a group | Child deny wins |
| Child allows; parent denies | Child allow wins; traversal has already stopped |
| Identity allows; a group denies at the same resource | Identity allow wins |
| First decisive group allows; a later group denies | First group's allow wins |
| No matching allow or deny anywhere in traversal | Default deny |

Group ordering can therefore change a decision. Use a deliberate order and avoid depending on unspecified backend group iteration. Do not describe these semantics as aggregating all matching group policies. A single ACL entry is keyed by UUID, so ensure identity and group UUID namespaces do not collide.

For a given grantee/resource, `grantAccess` sets allow bits and clears the corresponding deny bits. `denyAccess` does the reverse. `revokeAccess` removes both allow and deny bits for that permission; it can reveal inherited/group access again rather than forcing deny.

Sources: [AclAuthorizationProvider.canAccess](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AclAuthorizationProvider.java), [AccessControlList](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AccessControlList.java). Behavior is exercised by [ACL grant tests](../src/test/java/io/mapsmessaging/security/authorisation/impl/acl/AclAuthorizationProviderGrantTest.java) and [namespace traversal tests](../src/test/java/io/mapsmessaging/security/authorisation/AbstractNamespaceTraversalAuthorizationTest.java).

## Resource traversal and inheritance

`ResourceTraversal` supplies `current()`, `hasMore()` and `moveToParent()`. `ResourceTraversalFactory` creates a fresh traversal for each check. Its default implementation visits only the exact resource, so slash-separated IDs do not inherit automatically.

The example supplies an application traversal visiting `fleet/site/telemetry`, `fleet/site`, `fleet` and the empty root. Every ancestor retains the original resource type and tenant. It never crosses tenant boundaries. These root/path rules belong to the example, not to the default library traversal. Adapt them to your resource model and validate IDs before checking or granting access.

ACL inheritance is evaluated during access checks. It does not copy a parent's grants onto each child. A later parent policy change affects a child whose traversal reaches that parent, subject to cached decisions. Local policy can stop traversal before the parent is examined.

Sources: [ResourceTraversal](../src/main/java/io/mapsmessaging/security/authorisation/ResourceTraversal.java), [ResourceTraversalFactory](../src/main/java/io/mapsmessaging/security/authorisation/ResourceTraversalFactory.java), [DefaultResourceTraversal](../src/main/java/io/mapsmessaging/security/authorisation/DefaultResourceTraversal.java), [test traversal](../src/test/java/io/mapsmessaging/security/authorisation/NamespaceTraversal.java).

## Grants and diagnostics

Use `grant(identity, permission, resource)` or `grant(group, permission, resource)` for the convenience allow methods. Explicit operations accept `Grantee.forIdentity(identity)` or `Grantee.forGroup(group)`:

```java
provider.grantAccess(Grantee.forGroup(operators), readPermission, parent);
provider.denyAccess(Grantee.forIdentity(alice), readPermission, child);
provider.revokeAccess(Grantee.forIdentity(alice), readPermission, child);
```

The names above are integration variables; the complete executable example provides their concrete types and initialization.

`explainAccess` returns an `AccessDecision` with a boolean, structured `DecisionReason` and contributing grants/groups. ACL reasons distinguish explicit identity, explicit group, inherited resource and default deny. `explainEffectiveAccess` evaluates every permission registered with that ACL provider and returns allowed/denied sets plus per-permission decisions. A default-denied permission appears in the denied set even when there is no explicit deny entry.

Treat `detailMessage` as human-readable diagnostic text, not a stable format. Provider interfaces default unsupported diagnostic/management operations to `UnsupportedOperationException`; for example the Open provider does not implement the explain methods. Verify support for the chosen provider.

ACL `getGrantsForIdentity`, `getGrantsForGroup` and `getGrantsForResource` are not a complete deny-policy dump. The current ACL implementation derives these collections from allow masks; the identity form also incorporates its group allow masks. Use `explainAccess` for the actual decision path rather than interpreting these collections as a full effective-policy evaluation.

Sources: [AccessDecision](../src/main/java/io/mapsmessaging/security/authorisation/AccessDecision.java), [EffectiveAccess](../src/main/java/io/mapsmessaging/security/authorisation/EffectiveAccess.java), [ACL explain tests](../src/test/java/io/mapsmessaging/security/authorisation/impl/acl/AclExplainTests.java), [AclAuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AclAuthorizationProvider.java).

## Ownership and resource lifecycle

`ResourceCreationContext` carries owner identity, parent resource and `ResourceInitialGrantPolicy`. The enum defines `NONE`, `OWNER_MANAGE`, `OWNER_FULL` and `INHERIT_FROM_PARENT`, but the supplied providers do not automatically implement those policy names:

| Operation | Current ACL behavior | Current OpenFGA behavior |
| --- | --- | --- |
| `registerResource(resource, context)` | Creates an empty ACL and saves state; ignores the creation context | No-op; resources are materialized by relationship tuples |
| Owner policy | No implicit owner rights; explicit grants are required | Registration does not install owner tuples |
| Parent policy | Access inheritance depends on traversal, not the creation context | Registration does not install parent tuples |
| `deleteResource(resource)` | Removes that resource's local ACL and saves state | No standalone deletion; tuple revocation is required |

The example deliberately checks that `OWNER_FULL` does not grant ACL read access. If your application promises owner rights, install the required explicit permissions as part of its creation workflow and handle failure/rollback at that boundary. Removing a local ACL does not necessarily deny access: a parent grant may become visible. ACL resource deletion is exact-resource removal; it does not recursively remove descendant ACLs.

`deleteIdentity` and `deleteGroup` on ACL remove that UUID from every ACL and save state. ACL group membership checks use the `Identity` object's group list; its `addGroupMember`/`removeGroupMember` hooks do not maintain a separate membership database. Keep identity/group mappings and session identity snapshots current. The API's default `setGroupsForIdentity` is a no-op unless a concrete provider overrides it.

Sources: [ResourceCreationContext](../src/main/java/io/mapsmessaging/security/authorisation/ResourceCreationContext.java), [ResourceInitialGrantPolicy](../src/main/java/io/mapsmessaging/security/authorisation/ResourceInitialGrantPolicy.java), [AclAuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AclAuthorizationProvider.java), [OpenFGAAuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/impl/openfga/OpenFGAAuthorizationProvider.java).

## ACL persistence and batching

Factory-created ACL providers load `.acl_enc.dat` from `configDirectory` (default `.`). The factory retrieves or creates the `acl.state.key` private-key alias in the configured certificate store and derives an AES key from it. Preserve the key store alongside encrypted state; the state file alone is insufficient for recovery.

The direct constructor used by the example takes an already decoded state string, the permission array, an `AclSaveState` and a traversal factory. The example generates an ephemeral AES key and demonstrates reloading with that same key through `AclLoadState`. It deletes the file at exit and intentionally does not offer durable key management.

State is JSON compressed with GZIP and encrypted using AES-GCM with a fresh IV on each write. `AclLoadState` returns empty state for an absent file. Encrypted read/decryption errors can fail factory initialization with `IOException`. The provider logs malformed state JSON rather than guaranteeing initialization failure. Mutation methods update in-memory policy and call `writeState`; that method catches/logs persistence exceptions, so a successful void grant/revoke call does not guarantee durable storage.

Calling `startBatch(timeout)` on a direct ACL provider suppresses writes; `stopBatch()` enables and performs a write. `timeout` is not used by ACL and batching does not provide transactions, rollback or atomic multi-grant policy visibility. Always finish a batch in a `finally` block. The cache wrapper does not forward these batch methods, so calling them on a factory-returned cached provider does not enable ACL batching.

Sources: [AclAuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AclAuthorizationProvider.java), [AclSaveState](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AclSaveState.java), [AclLoadState](../src/main/java/io/mapsmessaging/security/authorisation/impl/acl/AclLoadState.java), [persistence tests](../src/test/java/io/mapsmessaging/security/authorisation/impl/acl/AclStatePersistenceTest.java).

## Authorization cache

`CachingAuthorizationProvider` caches booleans for an identity object, permission name and resource. A cache hit returns the stored decision until expiry. In the refresh-ahead interval it may queue a delegate check while returning the existing value. The factory default TTL is 10 seconds; directly constructing the wrapper with a null TTL falls back to 3 seconds. Refresh-ahead defaults to 500 ms.

| Call through the wrapper | Cache behavior |
| --- | --- |
| `canAccess`, `hasAllAccess`, `hasOneAccess` | Use cached booleans |
| `explainAccess`, `explainEffectiveAccess` | Delegate immediately, bypassing the boolean cache |
| `grantAccess`, `denyAccess`, `revokeAccess` | Delegate, then clear the cache |
| Identity/group register/delete and individual member add/remove | Delegate, then clear the cache |
| `registerResource`, `deleteResource` | Delegate without clearing the cache |
| `setGroupsForIdentity` | Inherits the interface no-op; does not forward to the delegate or clear the cache |
| `startBatch`, `stopBatch` | Inherit interface no-ops; do not forward to the delegate |
| `reset` | Resets the delegate policy and clears the cache; it is destructive policy reset, not cache-only invalidation |
| `shutdown` | Shuts down its executor; it does not close the delegate |

`Identity` does not define value equality by UUID, so the identity part of the cache key uses object identity. Creating another `Identity` with the same UUID does not address the same cache entry; mutating the groups of an already cached object does not change that key. Permission names must be unique, and resources use their value equality.

Changes made directly to the delegate, remotely in OpenFGA or by mutating an identity snapshot bypass wrapper invalidation. Diagnostics may therefore disagree temporarily with `canAccess`, and resource deletion can leave a previously cached allow until it is refreshed/expired. Cache clearing does not cancel already queued refresh tasks, so do not treat it as a synchronization barrier against concurrent policy changes. Configure caching according to your required revocation consistency rather than assuming immediate global revocation.

The wrapper exposes `getDelegate()` for inspection, but sending mutations to that delegate bypasses invalidation. Keep application updates on the intended provider boundary. Call `shutdown()` when retiring a wrapper. If an executor is explicitly supplied, note that wrapper shutdown shuts down that executor too; define ownership accordingly.

Sources: [CachingAuthorizationProvider](../src/main/java/io/mapsmessaging/security/authorisation/impl/caching/CachingAuthorizationProvider.java), [AuthorizationProviderFactory](../src/main/java/io/mapsmessaging/security/authorisation/AuthorizationProviderFactory.java), [Identity](../src/main/java/io/mapsmessaging/security/access/Identity.java).

## OpenFGA integration boundary

The provider translates explicit allows to `allow_` plus the lower-case permission name and denies to `deny_` plus that name, using configured relationship model conventions. Group grants refer to a group's member userset. The service/model must already support the expected object types and relations. An ACL permission mask alone does not create an OpenFGA model.

Do not infer identical allow/deny precedence, ownership creation or deletion semantics across providers. Review the concrete provider and the deployed model. The [OpenFGA test model](../src/test/resources/openfga-model.json) and [provider implementation](../src/main/java/io/mapsmessaging/security/authorisation/impl/openfga/OpenFGAAuthorizationProvider.java) show the repository's conventions; tests relying on a remote service are not an offline guarantee. See [configuration](../Config.md) for connection settings.

For a complete connection lifecycle, start with [authentication](authentication.md), then resolve stable identity/group mappings before invoking these authorization APIs.
