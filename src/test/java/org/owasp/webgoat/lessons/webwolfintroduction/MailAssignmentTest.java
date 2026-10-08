/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.client.RestTemplate;

class MailAssignmentTest extends LessonTest {

  @MockBean private RestTemplate restTemplate;

  @Test
  void reversedUsernameIsNotTheCode() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/WebWolf/mail").param("uniqueCode", "tset"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void codeFromTheEmailSolvesTheAssignment() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/WebWolf/mail/send").param("email", "test@webgoat.org"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    ArgumentCaptor<Object> mail = ArgumentCaptor.forClass(Object.class);
    verify(restTemplate).postForEntity(anyString(), mail.capture(), eq(Object.class));
    String contents = ((Email) mail.getValue()).getContents();
    String code = contents.substring(contents.lastIndexOf("your unique code is: ") + 21);
    Assertions.assertThat(code).isNotEqualTo("tset").hasSizeGreaterThanOrEqualTo(6);

    mockMvc
        .perform(MockMvcRequestBuilders.post("/WebWolf/mail").param("uniqueCode", code))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  void emailWithoutAtSignGetsNormalAnswer() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/WebWolf/mail/send").param("email", "nobody"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
