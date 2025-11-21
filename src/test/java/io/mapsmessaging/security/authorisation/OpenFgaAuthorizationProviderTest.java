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

package io.mapsmessaging.security.authorisation;

import dev.openfga.sdk.api.client.OpenFgaClient;
import dev.openfga.sdk.api.client.model.*;
import dev.openfga.sdk.api.configuration.ClientConfiguration;
import dev.openfga.sdk.api.configuration.ClientReadOptions;
import dev.openfga.sdk.api.configuration.ClientWriteOptions;
import dev.openfga.sdk.api.model.Tuple;
import dev.openfga.sdk.api.model.TupleKey;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import io.mapsmessaging.security.authorisation.impl.openfga.OpenFGAAuthorizationProvider;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class OpenFgaAuthorizationProviderTest extends AbstractAuthorizationProviderTest{


  @Override
  protected AuthorizationProvider createAuthorizationProvider()throws Exception{
    ClientConfiguration clientConfiguration = new ClientConfiguration();
    clientConfiguration.apiUrl("http://10.140.62.152:8080");
    clientConfiguration.storeId("01KAF6PKR6YRJZ8RXXYXAJDX1E");
    clientConfiguration.connectTimeout(Duration.ofMillis(10000));
    OpenFgaClient client = new OpenFgaClient(clientConfiguration);

    List<TupleKey> tuplets = getAllTuples(client);
    deleteAllTuples(client, tuplets, "01KAF6SSMG4T5WZY47FS12QZ0C");
    return new OpenFGAAuthorizationProvider(client, "01KAF6SSMG4T5WZY47FS12QZ0C",  TestPermissions.values(),null, null, null, null);
  }

  public static List<TupleKey> getAllTuples(OpenFgaClient openFgaClient) throws FgaInvalidParameterException {
    List<TupleKey> result = new ArrayList<>();
    String continuationToken = null;

    do {
      ClientReadRequest request = new ClientReadRequest();

      ClientReadOptions options = new ClientReadOptions()
          .pageSize(100)                 // or whatever page size you like
          .continuationToken(continuationToken);

      ClientReadResponse response;
      try {
        response = openFgaClient.read(request, options).get();
      } catch (InterruptedException interruptedException) {
        Thread.currentThread().interrupt();
        throw new RuntimeException("Interrupted while reading tuples from OpenFGA", interruptedException);
      } catch (ExecutionException executionException) {
        throw new RuntimeException("Failed to read tuples from OpenFGA", executionException);
      }

      if (response.getTuples() != null) {
        for (Tuple tuple : response.getTuples()) {
          result.add(tuple.getKey());
        }
      }

      continuationToken = response.getContinuationToken();
    } while (continuationToken != null && !continuationToken.isEmpty());

    return result;
  }

  public static void deleteAllTuples(OpenFgaClient openFgaClient, List<TupleKey> allTuples, String defaultId) throws FgaInvalidParameterException {
    if (allTuples.isEmpty()) {
      return;
    }
    List<ClientTupleKeyWithoutCondition> clientList = allTuples.stream()
        .map(t -> new ClientTupleKeyWithoutCondition()
            .user(t.getUser())
            .relation(t.getRelation())
            ._object(t.getObject()))
        .toList();
    ClientWriteRequest request = new ClientWriteRequest()
        .deletes(clientList);

    ClientWriteOptions options = new ClientWriteOptions()
        .authorizationModelId(defaultId);

    try {
      openFgaClient.write(request, options).get();
    } catch (InterruptedException interruptedException) {
      Thread.currentThread().interrupt();
      throw new RuntimeException("Interrupted while deleting tuples from OpenFGA", interruptedException);
    } catch (ExecutionException executionException) {
      throw new RuntimeException("Failed to delete tuples from OpenFGA", executionException);
    }
  }

}
/*
{
  "store": {
    "created_at":"2025-11-19T23:20:24.075622Z",
    "id":"01KAF6PKR6YRJZ8RXXYXAJDX1E",
    "name":"mapsmessaging",
    "updated_at":"2025-11-19T23:20:24.075622Z"
  }
}

{
  "authorization_model_id":"01KAF6SSMG4T5WZY47FS12QZ0C"
}
 */