/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class CSRFLoginTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void sessionFromCrossSiteLoginIsRefused() throws Exception {
    MockHttpSession session = new MockHttpSession();
    session.setAttribute(LoginOriginRecorder.LOGIN_ORIGIN_VERIFIED, false);
    mockMvc
        .perform(post("/csrf/login").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("refused")));
  }

  @Test
  void sessionWithoutRecordedLoginOriginIsRefused() throws Exception {
    mockMvc
        .perform(post("/csrf/login"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void sameOriginLoginDoesNotCompleteTheAssignment() throws Exception {
    MockHttpSession session = new MockHttpSession();
    session.setAttribute(LoginOriginRecorder.LOGIN_ORIGIN_VERIFIED, true);
    mockMvc
        .perform(post("/csrf/login").session(session))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void recorderFlagsCrossSiteLogin() throws Exception {
    MockHttpServletRequest request = loginRequest("http://localhost:9090/WebWolf/files/x.html");
    new LoginOriginRecorder().doFilter(request, new MockHttpServletResponse(), loginChain());
    assertThat(request.getSession().getAttribute(LoginOriginRecorder.LOGIN_ORIGIN_VERIFIED))
        .isEqualTo(false);
  }

  @Test
  void recorderTrustsSameOriginLogin() throws Exception {
    MockHttpServletRequest request = loginRequest("http://localhost:8080/WebGoat/login");
    new LoginOriginRecorder().doFilter(request, new MockHttpServletResponse(), loginChain());
    assertThat(request.getSession().getAttribute(LoginOriginRecorder.LOGIN_ORIGIN_VERIFIED))
        .isEqualTo(true);
  }

  private static MockHttpServletRequest loginRequest(String referer) {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/WebGoat/login");
    request.setContextPath("/WebGoat");
    request.setServletPath("/login");
    request.addHeader("Host", "localhost:8080");
    request.addHeader("Referer", referer);
    return request;
  }

  /** Simulates the login creating the authenticated session. */
  private static MockFilterChain loginChain() {
    return new MockFilterChain(
        new jakarta.servlet.http.HttpServlet() {},
        (req, res, chain) ->
            ((jakarta.servlet.http.HttpServletRequest) req).getSession(true));
  }
}
