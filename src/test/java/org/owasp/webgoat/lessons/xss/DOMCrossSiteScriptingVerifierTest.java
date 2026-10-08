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

class DOMCrossSiteScriptingVerifierTest extends LessonTest {

  private String phoneHome() throws Exception {
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
    return output.substring("phoneHome Response is ".length());
  }

  @Test
  void valueFromPhoneHomeDoesNotSolveFollowUp() throws Exception {
    String value = phoneHome();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/CrossSiteScripting/dom-follow-up")
                .param("successMessage", value))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void guessedOrMissingValueIsRefused() throws Exception {
    for (String guess : new String[] {"", "null", "0", "-1"}) {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/CrossSiteScripting/dom-follow-up")
                  .param("successMessage", guess))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    }
    mockMvc
        .perform(MockMvcRequestBuilders.post("/CrossSiteScripting/dom-follow-up"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
