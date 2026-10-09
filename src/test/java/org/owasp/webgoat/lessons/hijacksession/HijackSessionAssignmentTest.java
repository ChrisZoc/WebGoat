/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/***
 *
 * @author Angel Olle Blazquez
 *
 */
class HijackSessionAssignmentTest extends LessonTest {

  private static final String COOKIE_NAME = "hijack_cookie";
  private static final String LOGIN_CONTEXT_PATH = "/HijackSession/login";

  private MockHttpServletRequestBuilder post(String username, String password, String cookie) {
    MockHttpServletRequestBuilder request =
        MockMvcRequestBuilders.post(LOGIN_CONTEXT_PATH)
            .param("username", username)
            .param("password", password);
    if (cookie != null) {
      request.cookie(new Cookie(COOKIE_NAME, cookie));
    }
    return request;
  }

  @Test
  void loginIssuesHardenedCookieWithRandomSecret() throws Exception {
    mockMvc
        .perform(post("webgoat", "webgoat", null))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(
            header()
                .string(
                    "Set-Cookie",
                    Matchers.matchesPattern(COOKIE_NAME + "=[0-9]+-[0-9]+-[0-9a-f]{32}; .*")))
        .andExpect(header().string("Set-Cookie", Matchers.containsString("HttpOnly")))
        .andExpect(header().string("Set-Cookie", Matchers.containsString("Secure")))
        .andExpect(header().string("Set-Cookie", Matchers.containsString("SameSite=Strict")));
  }

  @Test
  void guessedSessionIdIsRefused() throws Exception {
    long now = System.currentTimeMillis();
    for (long ts = now - 5; ts <= now; ts++) {
      mockMvc
          .perform(post("", "", "1-" + ts))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    }
  }
}
