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

package io.mapsmessaging.sasl.provider.cram;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.logging.Level;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

/**
 * Implements the CRAM-MD5 SASL client-side mechanism.
 * (<A HREF="http://www.ietf.org/rfc/rfc2195.txt">RFC 2195</A>).
 * CRAM-MD5 has no initial response. It receives bytes from
 * the server as a challenge, which it hashes by using MD5 and the password.
 * It concatenates the authentication ID with this result and returns it
 * as the response to the challenge. At that point, the exchange is complete.
 *
 * @author Vincent Ryan
 * @author Rosanna Lee
 */
public final class CramMD5Client extends CramMD5Base implements SaslClient {
  private final String username;

  /**
   * Creates a SASL mechanism with client credentials that it needs
   * to participate in CRAM-MD5 authentication exchange with the server.
   *
   */
  public CramMD5Client(String authzid, String protocol, String serverName,
      Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    Object[] uinfo = getUserInfo("CRAM-MD5", authzid, cbh);

    username = (String) (uinfo[0]);
    pw = (byte[]) uinfo[1];
  }
  /**
   * Gets the authentication id and password. The
   * password is converted to bytes using UTF-8 and stored in bytepw.
   * The authentication id is stored in authId.
   *
   * @param prefix The non-null prefix to use for the prompt (e.g., mechanism
   *  name)
   * @param authorizationId The possibly null authorization id. This is used
   * as a default for the NameCallback. If null, it is not used in prompt.
   * @param cbh The non-null callback handler to use.
   * @return an {authid, passwd} pair
   */
  private Object[] getUserInfo(String prefix, String authorizationId,
      CallbackHandler cbh) throws SaslException {
    if (cbh == null) {
      throw new SaslException(
          "Callback handler to get username/password required");
    }
    try {
      String userPrompt = prefix + " authentication id: ";
      String passwdPrompt = prefix + " password: ";

      NameCallback ncb = authorizationId == null?
          new NameCallback(userPrompt) :
          new NameCallback(userPrompt, authorizationId);

      PasswordCallback pcb = new PasswordCallback(passwdPrompt, false);

      cbh.handle(new Callback[]{ncb,pcb});

      char[] pw = pcb.getPassword();

      byte[] bytepw;
      String authId;

      if (pw != null) {
        bytepw = new String(pw).getBytes(StandardCharsets.UTF_8);
        pcb.clearPassword();
      } else {
        bytepw = null;
      }

      authId = ncb.getName();

      return new Object[]{authId, bytepw};

    } catch (IOException e) {
      throw new SaslException("Cannot get password", e);
    } catch (UnsupportedCallbackException e) {
      throw new SaslException("Cannot get userid/password", e);
    }
  }
  /**
   * CRAM-MD5 has no initial response.
   */
  public boolean hasInitialResponse() {
    return false;
  }

  /**
   * Processes the challenge data.
   *
   * The server sends a challenge data using which the client must
   * compute an MD5-digest with its password as the key.
   *
   * @param challengeData A non-null byte array containing the challenge
   *        data from the server.
   * @return A non-null byte array containing the response to be sent to
   *        the server.
   * @throws SaslException If platform does not have MD5 support
   * @throw IllegalStateException if this method is invoked more than once.
   */
  public byte[] evaluateChallenge(byte[] challengeData)
      throws SaslException {

    // See if we've been here before
    if (completed) {
      throw new IllegalStateException(
          "CRAM-MD5 authentication already completed");
    }

    if (aborted) {
      throw new IllegalStateException(
          "CRAM-MD5 authentication previously aborted due to error");
    }

    // generate a keyed-MD5 digest from the user's password and challenge.
    try {
      if (logger.isLoggable(Level.FINE)) {
        logger.log(Level.FINE, "CRAMCLNT01:Received challenge: {0}",
            new String(challengeData, StandardCharsets.UTF_8));
      }

      String digest = HMAC_MD5(pw, challengeData);

      // clear it when we no longer need it
      clearPassword();

      // response is username + " " + digest
      String resp = username + " " + digest;

      logger.log(Level.FINE, "CRAMCLNT02:Sending response: {0}", resp);

      completed = true;

      return resp.getBytes(StandardCharsets.UTF_8);
    } catch (java.security.NoSuchAlgorithmException e) {
      aborted = true;
      throw new SaslException("MD5 algorithm not available on platform", e);
    }
  }
}