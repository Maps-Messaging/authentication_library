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

import static io.mapsmessaging.security.authorisation.OpenFgaAuthorizationProviderTest.deleteAllTuples;
import static io.mapsmessaging.security.authorisation.OpenFgaAuthorizationProviderTest.getAllTuples;

import dev.openfga.sdk.api.client.OpenFgaClient;
import dev.openfga.sdk.api.configuration.ClientConfiguration;
import dev.openfga.sdk.api.model.TupleKey;
import io.mapsmessaging.security.authorisation.impl.openfga.OpenFGAAuthorizationProvider;
import java.time.Duration;
import java.util.List;

public class OpenFgaAuthorizationProviderGrantTest extends AbstractAuthorizationProviderGrantTest{

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

}
