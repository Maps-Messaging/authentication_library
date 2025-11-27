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

package io.mapsmessaging.security.authorisation;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class PermissionRegistry {

  private static final Map<String, Permission> PERMISSIONS = new ConcurrentHashMap<>();

  private PermissionRegistry() {
    // utility class
  }

  public static void register(Permission permission) {
    Objects.requireNonNull(permission, "permission");
    String key = normalizeName(permission.getName());
    Permission existing = PERMISSIONS.putIfAbsent(key, permission);
    if (existing != null && existing != permission) {
      throw new IllegalStateException(
          "Duplicate permission name registered: " + permission.getName());
    }
  }

  public static void registerAll(Permission[] permissions) {
    if (permissions == null) {
      return;
    }
    for (Permission permission : permissions) {
      if (permission != null) {
        register(permission);
      }
    }
  }

  public static Permission find(String name) {
    if (name == null) {
      return null;
    }
    return PERMISSIONS.get(normalizeName(name));
  }

  public static Collection<Permission> all() {
    return Collections.unmodifiableCollection(PERMISSIONS.values());
  }

  private static String normalizeName(String name) {
    return name.toLowerCase(Locale.ROOT).trim();
  }
}
