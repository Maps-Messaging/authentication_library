/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.logging;

import io.mapsmessaging.logging.Category;
import io.mapsmessaging.logging.LEVEL;
import io.mapsmessaging.logging.LogMessage;
import lombok.Getter;

public enum AuthLogMessages implements LogMessage {

  //-------------------------------------------------------------------------------------------------------------

  // <editor-fold desc="SCRAM messages">
  SCRAM_SERVER_INITIAL_PHASE(LEVEL.INFO, AuthCategory.AUTHENTICATION, "SCRAM server initialising using algorithm {}"),
  SCRAM_SERVER_STATE_CHANGE(LEVEL.INFO, AuthCategory.AUTHENTICATION, "SCRAM server state changed to {}"),
  // </editor-fold>

  // <editor-fold desc="Password parser messages">
  PASSWORD_PARSER_LOADED(LEVEL.WARN, AuthCategory.AUTHENTICATION, "Loaded parser for {} with hash key {}"),
  IDENTITY_LOOKUP_LOADED(LEVEL.WARN, AuthCategory.AUTHENTICATION, "Loaded identity lookup supporting {}"),
  // </editor-fold>


  // <editor-fold desc="Generic messages">
  DO_NOT_USE_IN_PRODUCTION(LEVEL.AUTH, AuthCategory.AUTHENTICATION, "Warning !!!, Not to be used in a production environment"),
  USER_LOGGED_IN(LEVEL.DEBUG, AuthCategory.AUTHENTICATION, "User {} logged in"),
  NO_SUCH_USER_FOUND(LEVEL.INFO, AuthCategory.AUTHENTICATION, "User {} not found"),
  USER_LOGGED_OUT(LEVEL.DEBUG, AuthCategory.AUTHENTICATION, "User {} logged out"),
  // </editor-fold>

  // <editor-fold desc="File management log entries">
  FAILED_TO_CREATE_FILE(LEVEL.FATAL, AuthCategory.SUPPORT, "Failed to create new file {}"),
  FAILED_TO_DELETE_FILE(LEVEL.FATAL, AuthCategory.SUPPORT, "Failed to delete existing file {}"),
  FAILED_TO_RENAME_FILE(LEVEL.FATAL, AuthCategory.SUPPORT, "Failed to rename file {} to {}"),
  // </editor-fold>

  // <editor-fold desc="Ldap messages">
  LDAP_LOAD_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Failed to get user list"),
  // </editor-fold>

  // <editor-fold desc="Encrypted Auth messages">
  ENCRYPTED_LOAD_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Invalid configuration, unable to construct the requested auth"),
  // </editor-fold>


  // <editor-fold desc="Auth0 messages">
  AUTH0_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Failed to get user list"),
  AUTH0_REQUEST_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Failed to retrieve data from Auth0"),
  AUTH0_JWT_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Error detected in Auth0 JWT"),
  AUTH0_PASSWORD_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Error detected while retrieving JWT for user {}"),

  // </editor-fold>

  // <editor-fold desc="AWS messages">
  AWS_KEY_LOAD_FAILURE(LEVEL.FATAL, AuthCategory.AUTHENTICATION,  "Unable to load public key by Id: {} from {}"),
  AWS_INVALID_URL(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Invalid URL provided, URL={}"),
  // </editor-fold>

  // <editor-fold desc="SSL config  log messages">
  SSL_SERVER_INITIALISE(LEVEL.DEBUG, AuthCategory.SSL, "InitialedKey Manager Factory of type {}"),
  SSL_SERVER_TRUST_MANAGER(LEVEL.DEBUG, AuthCategory.SSL, "Initialised Trust Manager Factory of type {}"),
  SSL_SERVER_CONTEXT_CONSTRUCT(LEVEL.DEBUG, AuthCategory.SSL, "Constructing SSL Context with the created key and trust stores"),
  SSL_SERVER_SSL_CONTEXT_COMPLETE(LEVEL.DEBUG, AuthCategory.SSL, "Completed construction of the SSL Context with the created key and trust stores"),
  SSL_SERVER_LOAD_KEY_STORE(LEVEL.DEBUG, AuthCategory.SSL, "Loading Key Store {} of type {}"),
  SSL_SERVER_LOADED_KEY_STORE(LEVEL.DEBUG, AuthCategory.SSL, "Loaded Key Store {} of type {}"),
  // </editor-fold>

  CRL_SUCCESS(LEVEL.INFO, AuthCategory.SSL, "Successfully reloaded the CRL from {}"),
  CRL_FAILURE(LEVEL.FATAL, AuthCategory.SSL, "Failed to reloaded the CRL from {}"),

  // <editor-fold desc="Password file messages">
  PASSWORD_FILE_LOADED(LEVEL.INFO, AuthCategory.AUTHENTICATION, "Successfully loaded {} entries for {}"),
  PASSWORD_FILE_LOAD_EXCEPTION(LEVEL.FATAL, AuthCategory.AUTHENTICATION, "Password load failed for {} at line number {} "),
  PASSWORD_FILE_CHANGE_DETECTED(LEVEL.DEBUG, AuthCategory.AUTHENTICATION, "Password file change detected on {}"),
  CHECKING_PASSWORD_STORE(LEVEL.DEBUG, AuthCategory.AUTHENTICATION, "Scanning for password file changes on file {}");
  // </editor-fold>

  @Getter
  private final String message;
  @Getter
  private final LEVEL level;
  @Getter
  private final Category category;
  @Getter
  private final int parameterCount;

  AuthLogMessages(LEVEL level, AuthCategory category, String message) {
    this.message = message;
    this.level = level;
    this.category = category;
    int location = message.indexOf("{}");
    int count = 0;
    while (location != -1) {
      count++;
      location = message.indexOf("{}", location + 2);
    }
    this.parameterCount = count;
  }

  public enum AuthCategory implements Category {
    SUPPORT("Support"),
    SSL("SSL"),
    AUTHORISATION("Authorisation"),
    AUTHENTICATION("Authentication"),
    SASL("Sasl"),
    JAAS("Jaas");


    @Getter
    private final String description;

    AuthCategory(String description) {
      this.description = description;
    }

    public String getDivision() {
      return "Security";
    }
  }
}
