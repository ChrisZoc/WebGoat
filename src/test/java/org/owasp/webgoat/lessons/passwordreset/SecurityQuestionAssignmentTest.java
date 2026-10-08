/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

public class SecurityQuestionAssignmentTest extends LessonTest {

  private MockMvc mockMvc;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void oneQuestionShouldNotSolveTheAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/SecurityQuestions")
                .param("question", "What is your favorite animal?"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback", CoreMatchers.is(messages.getMessage("password-questions-weak"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(jsonPath("$.output", CoreMatchers.notNullValue()));
  }

  @Test
  public void twoWeakQuestionsShouldNotSolveTheAssignment() throws Exception {
    MockHttpSession mocksession = new MockHttpSession();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/SecurityQuestions")
                .param("question", "What is your favorite animal?")
                .session(mocksession))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/SecurityQuestions")
                .param("question", "What is your favorite color?")
                .session(mocksession))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.output", CoreMatchers.notNullValue()))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void unknownQuestionGetsNormalAnswer() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/SecurityQuestions")
                .param("question", "What is the airspeed velocity of an unladen swallow?"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(
            jsonPath("$.output", CoreMatchers.is("Unknown question, please try again...")));
  }
}
