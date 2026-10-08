/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class StoredCrossSiteScriptingVerifierTest extends LessonTest {

  @Test
  void phoneHomeResponseDoesNotSolveStoredFollowUp() throws Exception {
    String body =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/CrossSiteScripting/phone-home-xss")
                    .header("webgoat-requested-by", "dom-xss-vuln")
                    .param("param1", "42")
                    .param("param2", "24"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    String output = JsonPath.read(body, "$.output");
    String value = output.substring("phoneHome Response is ".length());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss-follow-up")
                .param("successMessage", value))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void missingOrGuessedValueIsRefused() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss-follow-up"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss-follow-up")
                .param("successMessage", "null"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
