/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.hijacksession.cas.HijackSessionAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MvcResult;
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

  @Autowired HijackSessionAuthenticationProvider provider;

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

  private String issuedCookie() throws Exception {
    MvcResult result =
        mockMvc.perform(post("webgoat", "webgoat", null)).andExpect(status().isOk()).andReturn();
    return result.getResponse().getCookie(COOKIE_NAME).getValue();
  }

  @Test
  void loginIssuesRandomOpaqueHardenedCookie() throws Exception {
    mockMvc
        .perform(post("webgoat", "webgoat", null))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(header().string("Set-Cookie", Matchers.containsString("HttpOnly")))
        .andExpect(header().string("Set-Cookie", Matchers.containsString("Secure")))
        .andExpect(header().string("Set-Cookie", Matchers.containsString("SameSite=Strict")));

    String a = issuedCookie();
    String b = issuedCookie();
    assertThat(a).isNotEqualTo(b).matches("[A-Za-z0-9_-]{43}");
  }

  @Test
  void blankCredentialsGetNoSession() throws Exception {
    MvcResult result =
        mockMvc
            .perform(post("", "", null))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
            .andReturn();
    assertThat(result.getResponse().getCookie(COOKIE_NAME)).isNull();
  }

  @Test
  void foreignSessionIdIsNeverAccepted() throws Exception {
    // a session the server issued to another WebGoat user
    String victimId = provider.login("victim", "victim", "secret").getId();

    String[][] attempts = {{"", ""}, {"victim", "x"}, {"webgoat", "webgoat"}};
    for (String[] creds : attempts) {
      mockMvc
          .perform(post(creds[0], creds[1], victimId))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    }
  }

  @Test
  void forgedSessionIdIsNeverAccepted() throws Exception {
    for (String forged : new String[] {"1-1700000000000", "anyId", "value"}) {
      mockMvc
          .perform(post("", "", forged))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    }
  }

  @Test
  void ownSessionIsRecognisedButNeverCompletes() throws Exception {
    String own = issuedCookie();
    mockMvc
        .perform(post("webgoat", "webgoat", own))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(jsonPath("$.feedback", Matchers.containsString("still valid")));
  }
}
