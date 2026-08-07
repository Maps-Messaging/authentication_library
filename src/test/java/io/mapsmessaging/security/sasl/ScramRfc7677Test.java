/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

package io.mapsmessaging.security.sasl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.util.Base64;
import javax.crypto.Mac;
import org.junit.jupiter.api.Test;

class ScramRfc7677Test {

  @Test
  void computesPublishedScramSha256ProofAndVerifier() throws Exception {
    String clientFirstBare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
    String serverFirst = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    String clientFinalWithoutProof = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    String authMessage = clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof;

    SessionContext context = new SessionContext();
    context.setMac(Mac.getInstance("HmacSHA256"));
    context.setPasswordSalt(Base64.getDecoder().decode("W22ZaJ0SNY7soEsUEjb6gQ=="));
    context.setIterations(4096);
    context.computeClientHashes("pencil".toCharArray(), authMessage);
    context.computeServerSignature("pencil".toCharArray(), authMessage);

    assertEquals("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", Base64.getEncoder().encodeToString(context.getClientProof()));
    assertEquals("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=", Base64.getEncoder().encodeToString(context.getServerSignature()));
  }

  @Test
  void parserPreservesWireOrderAndRejectsDuplicateOrMandatoryExtensions() throws Exception {
    ChallengeResponse response = new ChallengeResponse("n,,n=user,r=nonce");
    assertEquals("n,,", response.getGs2Header());
    assertEquals("n=user,r=nonce", response.getBareMessage());
    assertEquals("n,,n=user,r=nonce", response.toString());

    assertThrows(IOException.class, () -> new ChallengeResponse("n,,n=user,n=other,r=nonce"));
    assertThrows(IOException.class, () -> new ChallengeResponse("m=required,r=nonce"));
  }
}
