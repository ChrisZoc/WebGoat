/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class QuestionsAssignmentTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  private void answer(String username, String answer, boolean completed, String feedbackKey)
      throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/questions")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", username)
                .param("securityQuestion", answer))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(completed)))
        .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage(feedbackKey))));
  }

  @Test
  void guessedFavoriteColorDoesNotResetPassword() throws Exception {
    answer("tom", "purple", false, "password-questions-incorrect");
  }

  @Test
  void unknownUserGetsSameMessageAsWrongAnswer() throws Exception {
    answer("nobody-here", "red", false, "password-questions-incorrect");
  }

  @Test
  void bruteForcingColorsIsLimited() throws Exception {
    List<String> colors = List.of("red", "green", "blue");
    for (String color : colors) {
      answer("jerry", color, false, "password-questions-incorrect");
    }
    answer("jerry", "orange", false, "password-questions-locked");
  }
}
