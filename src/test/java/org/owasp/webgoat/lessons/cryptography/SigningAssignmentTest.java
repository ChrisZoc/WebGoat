/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import javax.xml.bind.DatatypeConverter;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class SigningAssignmentTest extends LessonTest {

  @Test
  void signatureMadeWithHandedOutKeyIsRefused() throws Exception {
    MockHttpSession session = new MockHttpSession();
    String pem =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/crypto/signing/getprivate").session(session))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

    PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPEM(pem);
    String modulus =
        DatatypeConverter.printHexBinary(
            ((RSAPrivateCrtKey) privateKey).getModulus().toByteArray());
    String signature = CryptoUtil.signMessage(modulus, privateKey);

    // the handed-out key is not the server's trusted signing key
    KeyPair serverKeyPair = (KeyPair) session.getAttribute("keyPair");
    assertThat(((RSAPublicKey) serverKeyPair.getPublic()).getModulus())
        .isNotEqualTo(((RSAPrivateCrtKey) privateKey).getModulus());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/crypto/signing/verify")
                .session(session)
                .param("modulus", modulus)
                .param("signature", signature))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void serverModulusWithForgedSignatureIsRefused() throws Exception {
    MockHttpSession session = new MockHttpSession();
    String pem =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/crypto/signing/getprivate").session(session))
            .andReturn()
            .getResponse()
            .getContentAsString();
    PrivateKey handedOut = CryptoUtil.getPrivateKeyFromPEM(pem);
    KeyPair serverKeyPair = (KeyPair) session.getAttribute("keyPair");
    String modulus =
        DatatypeConverter.printHexBinary(
            ((RSAPublicKey) serverKeyPair.getPublic()).getModulus().toByteArray());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/crypto/signing/verify")
                .session(session)
                .param("modulus", modulus)
                .param("signature", CryptoUtil.signMessage(modulus, handedOut)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
