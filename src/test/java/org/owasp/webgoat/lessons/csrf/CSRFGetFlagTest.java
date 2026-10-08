/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CSRFGetFlagTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void crossSiteRequestDoesNotGetAFlag() throws Exception {
    mockMvc
        .perform(
            post("/csrf/basic-get-flag")
                .header("Host", "localhost:8080")
                .header("Referer", "http://localhost:9090/WebWolf/files/fake.html")
                .param("csrf", "thisisnotchecked"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.flag", nullValue()));
  }

  @Test
  void requestWithoutRefererDoesNotGetAFlag() throws Exception {
    mockMvc
        .perform(post("/csrf/basic-get-flag").header("Host", "localhost:8080").param("csrf", "true"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.flag", nullValue()));
  }

  @Test
  void sameOriginRequestIsAnsweredWithoutFlag() throws Exception {
    mockMvc
        .perform(
            post("/csrf/basic-get-flag")
                .header("Host", "localhost:8080")
                .header("Referer", "http://localhost:8080/WebGoat/start.mvc")
                .param("csrf", "false"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.flag", nullValue()));
  }

  @Test
  void confirmingAFlagThatWasNeverIssuedFails() throws Exception {
    mockMvc
        .perform(post("/csrf/confirm-flag-1").param("confirmFlagVal", "12345"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
    mockMvc
        .perform(post("/csrf/confirm-flag-1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
