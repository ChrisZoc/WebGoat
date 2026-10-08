/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class BypassRestrictionsFieldRestrictionsTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void valuesOutsideTheFormRestrictionsAreRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/BypassRestrictions/FieldRestrictions")
                .param("select", "option3")
                .param("radio", "option3")
                .param("checkbox", "maybe")
                .param("shortInput", "123456")
                .param("readOnlyInput", "changed"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void valuesWithinTheFormRestrictionsDoNotSolveTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/BypassRestrictions/FieldRestrictions")
                .param("select", "option1")
                .param("radio", "option2")
                .param("checkbox", "on")
                .param("shortInput", "12345")
                .param("readOnlyInput", "change"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
