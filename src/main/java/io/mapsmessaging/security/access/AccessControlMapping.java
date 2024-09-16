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

package io.mapsmessaging.security.access;

/**
 * An interface for mapping between access control strings and corresponding bitset values.
 * Implementations of this interface define the access control keywords and their corresponding bitset values.
 * <p>
 * Example implementation:
 * An implementation can define a set of access control keywords and their corresponding bitset values.
 * For example, consider the following access control keywords:
 * - "Read": grants read access (bitset value 1)
 * - "Write": grants write access (bitset value 2)
 * - "Create": grants create access (bitset value 4)
 * - "Delete": grants delete access (bitset value 8)
 * <p>
 * An implementation can map these access control keywords to their respective bitset values.
 */
public interface AccessControlMapping {
  /**
   * Retrieves the bitset value associated with the given access control string.
   *
   * @param accessControl the access control string
   * @return the bitset value, or null if not found
   */
  Long getAccessValue(String accessControl);

  /**
   * Retrieves the String value associated with the given access value.
   *
   * @param value the access control value
   * @return the String value, or null if not found
   */
  String getAccessName(long value);

}
