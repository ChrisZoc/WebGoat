/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class HtmlTamperingTaskTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void tamperedPriceIsRefused() throws Exception {
    mockMvc
        .perform(post("/HtmlTampering/task").param("QTY", "2").param("Total", "1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("5999.98")));
  }

  @Test
  void correctPriceDoesNotCompleteTheAssignment() throws Exception {
    mockMvc
        .perform(post("/HtmlTampering/task").param("QTY", "2").param("Total", "5999.98"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void invalidQuantityIsRefusedWithoutError() throws Exception {
    mockMvc
        .perform(post("/HtmlTampering/task").param("QTY", "abc").param("Total", "0"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
    mockMvc
        .perform(post("/HtmlTampering/task").param("QTY", "-5").param("Total", "-14999.95"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
