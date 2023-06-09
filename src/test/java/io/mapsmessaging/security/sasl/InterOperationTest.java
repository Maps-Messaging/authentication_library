/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

package io.mapsmessaging.security.sasl;

import static com.ongres.scram.common.stringprep.StringPreparations.NO_PREPARATION;

import com.ongres.scram.client.NonceSupplier;
import com.ongres.scram.client.ScramClient;
import com.ongres.scram.client.ScramClient.ChannelBinding;
import com.ongres.scram.client.ScramSession;
import com.ongres.scram.common.util.CryptoUtil;
import org.junit.jupiter.api.Test;

public class InterOperationTest {

  @Test
  void checkScram(){
    ScramClient scramClient = ScramClient
        .channelBinding(ChannelBinding.NO)
        .stringPreparation(NO_PREPARATION)
        .selectMechanismBasedOnServerAdvertised("SCRAM-SHA-1")
        .nonceSupplier
            (new NonceSupplier() {
              @Override
              public String get() {
                return CryptoUtil.nonce(36);
              }
            })
        .setup();

    ScramSession scramSession = scramClient.scramSession("fred@google.com");
  }

}
