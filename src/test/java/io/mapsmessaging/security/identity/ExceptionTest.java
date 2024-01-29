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

import java.io.IOException;
import org.junit.jupiter.api.Test;

public class ExceptionTest {

  @Test
  void testDefaultConstructor() {
    IllegalFormatException exception = new IllegalFormatException();
    assertNull(exception.getMessage(), "Message should be null for default constructor");
  }

  @Test
  void testConstructorWithMessage() {
    String testMessage = "Test Reason";
    IllegalFormatException exception = new IllegalFormatException(testMessage);
    assertEquals(testMessage, exception.getMessage(), "Exception message should match the provided message");
  }

  @Test
  public void testIsIOException() {
    Exception exception = new IllegalFormatException();
    assertTrue(exception instanceof IOException, "IllegalFormatException should be an instance of IOException");
  }

}
