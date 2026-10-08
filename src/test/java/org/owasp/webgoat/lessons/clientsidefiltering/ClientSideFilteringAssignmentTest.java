/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * @author nbaars
 * @since 5/2/17.
 */
public class ClientSideFilteringAssignmentTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void leakedFreeCouponIsNoLongerAccepted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/clientSideFiltering/getItForFree")
                .param("checkoutCode", "get_it_for_free"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void publicCouponDoesNotMakeItFree() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/clientSideFiltering/getItForFree")
                .param("checkoutCode", "owasp-webgoat"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void wrongCouponCode() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/clientSideFiltering/getItForFree")
                .param("checkoutCode", "test"))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
