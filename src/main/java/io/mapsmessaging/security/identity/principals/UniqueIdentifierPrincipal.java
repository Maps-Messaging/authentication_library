/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.identity.principals;

import java.security.Principal;
import java.util.UUID;
import lombok.Getter;

@Getter
public class UniqueIdentifierPrincipal implements Principal {

  private final UUID authId;

  public UniqueIdentifierPrincipal(UUID authId) {
    this.authId = authId;
  }

  @Override
  public String getName() {
    return authId.toString();
  }

  @Override
  public String toString() {
    return "Unique Id : " + getName();
  }
}
