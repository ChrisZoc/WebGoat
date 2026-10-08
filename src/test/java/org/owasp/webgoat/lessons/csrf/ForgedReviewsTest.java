/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ForgedReviewsTest extends LessonTest {

  private static final String OLD_STATIC_TOKEN = "2aa14227b9a13d0bede0388a7fba9aa9";

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void forgedReviewWithStaticTokenFromOtherSiteIsRefused() throws Exception {
    mockMvc
        .perform(
            post("/csrf/review")
                .header("Host", "localhost:8080")
                .header("Referer", "http://localhost:9090/WebWolf/files/fake.html")
                .param("reviewText", "test review")
                .param("stars", "5")
                .param("validateReq", OLD_STATIC_TOKEN))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("refused")));
  }

  @Test
  void validTokenFromOtherSiteIsRefused() throws Exception {
    MockHttpSession session = new MockHttpSession();
    String token = fetchToken(session);
    mockMvc
        .perform(
            post("/csrf/review")
                .session(session)
                .header("Host", "localhost:8080")
                .header("Origin", "http://localhost:9090")
                .param("reviewText", "test review")
                .param("stars", "5")
                .param("validateReq", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("refused")));
  }

  @Test
  void reviewFromTheLessonPageIsPostedWithoutCompletingTheAssignment() throws Exception {
    MockHttpSession session = new MockHttpSession();
    String token = fetchToken(session);
    mockMvc
        .perform(
            post("/csrf/review")
                .session(session)
                .header("Host", "localhost:8080")
                .header("Referer", "http://localhost:8080/WebGoat/start.mvc")
                .param("reviewText", "my own review")
                .param("stars", "4")
                .param("validateReq", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("posted")));
  }

  private String fetchToken(MockHttpSession session) throws Exception {
    String body =
        mockMvc
            .perform(get("/csrf/review/token").session(session))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return JsonPath.read(body, "$.token");
  }
}
