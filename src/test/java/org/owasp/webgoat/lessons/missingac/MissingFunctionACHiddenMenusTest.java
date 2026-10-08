/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class MissingFunctionACHiddenMenusTest extends LessonTest {

  @Test
  void adminMenuItemsAreNotExposed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Users")
                .param("hiddenMenu2", "Config"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.not-exposed"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void reversedOrderIsRefusedAsWell() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Config")
                .param("hiddenMenu2", "Users"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void missingParametersGetARegularAnswer() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/access-control/hidden-menu"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void HiddenMenusFailure() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Foo")
                .param("hiddenMenu2", "Bar"))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.failure"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
