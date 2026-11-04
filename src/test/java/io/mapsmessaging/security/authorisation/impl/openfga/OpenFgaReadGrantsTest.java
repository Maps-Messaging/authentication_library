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

import static org.junit.jupiter.api.Assertions.*;

import dev.openfga.sdk.api.client.ApiResponse;
import dev.openfga.sdk.api.client.OpenFgaClient;
import dev.openfga.sdk.api.client.model.ClientReadRequest;
import dev.openfga.sdk.api.client.model.ClientReadResponse;
import dev.openfga.sdk.api.configuration.ClientConfiguration;
import dev.openfga.sdk.api.configuration.ClientReadOptions;
import dev.openfga.sdk.api.model.ReadResponse;
import dev.openfga.sdk.api.model.Tuple;
import dev.openfga.sdk.api.model.TupleKey;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import io.mapsmessaging.security.authorisation.Grant;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.TestPermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

class OpenFgaReadGrantsTest {

  private static final String USER = "user:" + UUID.randomUUID();

  @Test
  void skipsInvalidTuplesAndPreservesPaginationOrderAndDecisions() throws Exception {
    StubClient client = new StubClient(List.of(
        page("next", tuple("bad-user", "allow_read", "resource:tenant/topic"),
            tuple(USER, "allow_missing", "resource:tenant/topic"),
            tuple(USER, "allow_read", "invalid-object"),
            tuple(USER, "allow_read", "resource:tenant/topic")),
        page("", tuple(USER, "deny_read", "resource:tenant/topic"))), false);

    List<Grant> grants = new ArrayList<>(provider(client).readGrants(new ClientReadRequest()));

    assertEquals(2, grants.size());
    assertTrue(grants.get(0).isAllow());
    assertFalse(grants.get(1).isAllow());
    assertEquals("topic", grants.get(0).getProtectedResource().getResourceId());
    assertEquals(List.of("", "next"), client.tokens);
  }

  @Test
  void readFailureRetainsGrantsFromEarlierPages() throws Exception {
    StubClient client = new StubClient(
        List.of(page("next", tuple(USER, "allow_read", "resource:tenant/topic"))), true);

    assertEquals(1, provider(client).readGrants(new ClientReadRequest()).size());
    assertEquals(List.of("", "next"), client.tokens);
  }

  private static OpenFGAAuthorizationProvider provider(StubClient client) {
    return OpenFGAAuthorizationProvider.builder()
        .openFgaClient(client)
        .permission(new Permission[] {TestPermissions.READ})
        .build();
  }

  private static Tuple tuple(String user, String relation, String object) {
    return new Tuple().key(new TupleKey().user(user).relation(relation)._object(object));
  }

  private static ClientReadResponse page(String token, Tuple... tuples) {
    ReadResponse response = new ReadResponse().tuples(List.of(tuples)).continuationToken(token);
    return new ClientReadResponse(new ApiResponse<>(200, Map.of(), "", response));
  }

  private static final class StubClient extends OpenFgaClient {
    private final List<ClientReadResponse> pages;
    private final boolean failAfterPages;
    private final List<String> tokens = new ArrayList<>();

    private StubClient(List<ClientReadResponse> pages, boolean failAfterPages) throws FgaInvalidParameterException {
      super(new ClientConfiguration().apiUrl("http://localhost").storeId("01KAF6PKR6YRJZ8RXXYXAJDX1E"));
      this.pages = pages;
      this.failAfterPages = failAfterPages;
    }

    @Override
    public CompletableFuture<ClientReadResponse> read(ClientReadRequest request, ClientReadOptions options) {
      int index = tokens.size();
      tokens.add(options.getContinuationToken() == null ? "" : options.getContinuationToken());
      if (failAfterPages && index == pages.size()) {
        return CompletableFuture.failedFuture(new IllegalStateException("simulated read failure"));
      }
      return CompletableFuture.completedFuture(pages.get(index));
    }
  }
}
