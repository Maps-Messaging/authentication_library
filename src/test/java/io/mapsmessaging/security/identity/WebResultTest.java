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

package io.mapsmessaging.security.identity;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.identity.impl.external.WebResult;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class WebResultTest {

  @Test
  void testAllArgsConstructorAndGetterMethods() {
    Object expectedResult = "Test Result";
    long expectedExpiryTime = Instant.now().toEpochMilli();
    WebResult webResult = new WebResult(expectedResult, expectedExpiryTime);

    assertSame(expectedResult, webResult.getResult(), "The result should match what was set in the constructor");
    assertEquals(expectedExpiryTime, webResult.getExpiryTime(), "The expiry time should match what was set in the constructor");
  }

  @Test
  void testExpiryTimeBehavior() {
    long pastTime = Instant.now().minusSeconds(3600).toEpochMilli(); // 1 hour ago
    WebResult expiredWebResult = new WebResult(new Object(), pastTime);

    long currentTime = Instant.now().toEpochMilli();
    assertTrue(expiredWebResult.getExpiryTime() < currentTime, "The WebResult should be expired");
  }
}
