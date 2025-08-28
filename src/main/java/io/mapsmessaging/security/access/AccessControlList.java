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

package io.mapsmessaging.security.access;

import java.util.List;
import java.util.UUID;
import javax.security.auth.Subject;

public interface AccessControlList {

  String getName();

  AccessControlList create(AccessControlMapping accessControlMapping, List<String> config);

  long getSubjectAccess(Subject subject);

  boolean canAccess(Subject subject, long requestedAccess);

  boolean add(UUID uuid, long requestedAccess);

  boolean remove(UUID uuid, long requestedAccess);
}