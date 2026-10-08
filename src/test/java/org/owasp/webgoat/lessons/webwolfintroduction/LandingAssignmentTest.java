/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class LandingAssignmentTest extends LessonTest {

  @Test
  void reversedUsernameIsNotTheCode() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/WebWolf/landing").param("uniqueCode", "tset"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void codeFromThePasswordResetPageSolvesTheAssignment() throws Exception {
    MvcResult page =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/WebWolf/landing/password-reset"))
            .andExpect(status().isOk())
            .andReturn();
    String code = (String) page.getModelAndView().getModel().get("uniqueCode");
    Assertions.assertThat(code).isNotEqualTo("tset").hasSizeGreaterThanOrEqualTo(6);

    mockMvc
        .perform(MockMvcRequestBuilders.post("/WebWolf/landing").param("uniqueCode", code))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }
}
