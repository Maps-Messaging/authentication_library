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

package io.mapsmessaging.security.jaas;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Principal;
import org.junit.jupiter.api.Test;

public class PrinicipalTest {
  @Test
  void testGetPrincipal_InitiallyNull() {
    PrincipalCallback callback = new PrincipalCallback();
    assertNull(callback.getPrincipal(), "Initially, principal should be null");
  }

  @Test
  void testSetAndGetPrincipal() {
    PrincipalCallback callback = new PrincipalCallback();
    Principal testPrincipal = new Principal() {
      @Override
      public String getName() {
        return "TestPrincipal";
      }
    };

    callback.setPrincipal(testPrincipal);
    assertSame(testPrincipal, callback.getPrincipal(), "GetPrincipal should return the same Principal that was set");
  }
}
