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

package io.mapsmessaging.security.authorisation.impl.openfga;


import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.authorisation.AuthorizationProvider;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.ProtectedResource;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import javax.security.auth.Subject;
import lombok.Builder;

public class OpenFGAAuthorizationProvider implements AuthorizationProvider {

  private final HttpClient httpClient;
  private final URI baseUri;
  private final String storeId;
  private final String authorizationModelId;
  private final String apiToken;
  private final Duration timeout;

  @Builder
  public OpenFGAAuthorizationProvider(String baseUrl,
                                      String storeId,
                                      String authorizationModelId,
                                      String apiToken,
                                      Duration timeout) {
    this.baseUri = URI.create(baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl);
    this.storeId = storeId;
    this.authorizationModelId = authorizationModelId;
    this.apiToken = apiToken;
    this.timeout = timeout != null ? timeout : Duration.ofSeconds(2);
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(this.timeout)
        .build();
  }


  @Override
  public boolean canAccess(Subject subject,
                           Permission permission,
                           ProtectedResource protectedResource) {

    String path = "/stores/" + storeId + "/check";
    URI uri = baseUri.resolve(path);

    String user = toFgaUser(subject);
    String relation = permission.getName();
    String object = toFgaObject(protectedResource);

    String requestBody = """
        {
          "tuple_key": {
            "user": "%s",
            "relation": "%s",
            "object": "%s"
          }%s
        }
        """.formatted(
        escapeJson(user),
        escapeJson(relation),
        escapeJson(object),
        authorizationModelId != null && !authorizationModelId.isEmpty()
            ? ",\"authorization_model_id\":\"" + escapeJson(authorizationModelId) + "\""
            : ""
    );

    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(uri)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8));

    if (apiToken != null && !apiToken.isEmpty()) {
      builder.header("Authorization", "Bearer " + apiToken);
    }

    HttpRequest request = builder.build();

    try {
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() / 100 != 2) {
        return false;
      }
      return parseAllowed(response.body());
    } catch (IOException | InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  @Override
  public void grantAccess(Subject subject,
                          Permission permission,
                          ProtectedResource protectedResource) {

    writeTuple(subject, permission, protectedResource, true);
  }

  @Override
  public void revokeAccess(Subject subject,
                           Permission permission,
                           ProtectedResource protectedResource) {

    writeTuple(subject, permission, protectedResource, false);
  }

  private void writeTuple(Subject subject,
                          Permission permission,
                          ProtectedResource protectedResource,
                          boolean add) {

    String path = "/stores/" + storeId + "/write";
    URI uri = baseUri.resolve(path);

    String user = toFgaUser(subject);
    String relation = permission.getName();
    String object = toFgaObject(protectedResource);

    String tupleJson = """
        {
          "user": "%s",
          "relation": "%s",
          "object": "%s"
        }
        """.formatted(
        escapeJson(user),
        escapeJson(relation),
        escapeJson(object)
    );

    String sectionName = add ? "writes" : "deletes";

    String requestBody = """
        {
          "%s": {
            "tuple_keys": [
              %s
            ]
          }%s
        }
        """.formatted(
        sectionName,
        tupleJson,
        authorizationModelId != null && !authorizationModelId.isEmpty()
            ? ",\"authorization_model_id\":\"" + escapeJson(authorizationModelId) + "\""
            : ""
    );

    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(uri)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8));

    if (apiToken != null && !apiToken.isEmpty()) {
      builder.header("Authorization", "Bearer " + apiToken);
    }

    HttpRequest request = builder.build();

    try {
      httpClient.send(request, HttpResponse.BodyHandlers.discarding());
    } catch (IOException | InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private String toFgaUser(Subject subject) {
    // Adapt this to your Subject model (id/username/etc)
    return "user:" + SubjectHelper.getUniqueId(subject);
  }

  private String toFgaObject(ProtectedResource protectedResource) {
    // type:id form
    String type = protectedResource.getResourceType();
    String name = protectedResource.getResourceId();
    return type + ":" + name;
  }

  private boolean parseAllowed(String body) {
    int idx = body.indexOf("\"allowed\"");
    if (idx < 0) {
      return false;
    }
    int colon = body.indexOf(':', idx);
    if (colon < 0) {
      return false;
    }
    String tail = body.substring(colon + 1).trim();
    return tail.startsWith("true");
  }

  private String escapeJson(String value) {
    if (value == null) {
      return "";
    }
    return value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"");
  }
}
