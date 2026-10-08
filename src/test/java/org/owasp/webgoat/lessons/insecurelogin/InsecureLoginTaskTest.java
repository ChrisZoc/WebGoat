/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class InsecureLoginTaskTest extends LessonTest {

  @Test
  void leakedPlaintextCredentialsAreRefused() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .param("username", "CaptainJack")
                .param("password", "BlackPearl"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("insecure-login.intercept.failure"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void missingParametersGetARegularAnswer() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/task"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void clientScriptDoesNotContainCredentials() throws Exception {
    String script;
    try (var in = getClass().getResourceAsStream("/lessons/insecurelogin/js/credentials.js")) {
      script = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    assertThat(script).doesNotContain("\\x43\\x61", "BlackPearl", "CaptainJack", "password");
  }
}
