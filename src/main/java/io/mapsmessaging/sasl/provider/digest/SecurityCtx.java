/*
 * Copyright [ 2020 - 2022 ] [Matthew Buckton]
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

package io.mapsmessaging.sasl.provider.digest;

import javax.security.sasl.SaslException;

/**
 * Interface used for classes implementing integrity checking and privacy
 * for DIGEST-MD5 SASL mechanism implementation.
 *
 * @see <a href="http://www.ietf.org/rfc/rfc2831.txt">RFC 2831</a>
 * - Using Digest Authentication as a SASL Mechanism
 *
 * @author Jonathan Bruce
 */

interface SecurityCtx {

  /**
   * Wrap out-going message and return wrapped message
   *
   * @throws SaslException
   */
  byte[] wrap(byte[] dest, int start, int len)
      throws SaslException;

  /**
   * Unwrap incoming message and return original message
   *
   * @throws SaslException
   */
  byte[] unwrap(byte[] outgoing, int start, int len)
      throws SaslException;
}