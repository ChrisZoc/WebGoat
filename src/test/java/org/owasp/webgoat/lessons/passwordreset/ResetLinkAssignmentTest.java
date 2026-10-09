/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ResetLinkAssignmentTest extends LessonTest {

  @Value("${webwolf.host}")
  private String webWolfHost;

  @Value("${webwolf.port}")
  private String webWolfPort;

  @Autowired private ResourceLoader resourceLoader;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void wrongResetLink() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", "test"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutPasswordShouldReturnPasswordForm() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(MockMvcRequestBuilders.post("/PasswordReset/reset/change-password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutLinkShouldReturnPasswordLinkNotFound() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                    .param("password", "new_password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Autowired private ResetTokenStore tokenStore;

  private static org.springframework.test.web.servlet.ResultMatcher notCompleted() {
    return org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath(
            "$.lessonCompleted")
        .value(false);
  }

  @Test
  void forgedHostHeaderIsHandledLikeANormalRequestAndNeverSolves() throws Exception {
    tokenStore.clear();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", TOM_EMAIL)
                .header(HttpHeaders.HOST, webWolfHost + ":" + webWolfPort)
                .header("X-Forwarded-Host", webWolfHost + ":" + webWolfPort))
        .andExpect(status().isOk())
        .andExpect(notCompleted())
        .andExpect(
            org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath(
                    "$.feedback")
                .value(
                    org.hamcrest.Matchers.containsString(
                        "An e-mail has been send to " + TOM_EMAIL)));
    // a token is issued for Tom's own account, whatever the Host header said
    Assertions.assertThat(tokenStore.size()).isEqualTo(1);
    // ... and the Tom login still fails: the token is useless outside Tom's account
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "123456"))
        .andExpect(status().isOk())
        .andExpect(notCompleted());
  }

  @Test
  void resetRequestsAreRateLimited() throws Exception {
    tokenStore.clear();
    for (int i = 0; i < ResetTokenStore.MAX_REQUESTS_PER_WINDOW + 3; i++) {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post(
                      "/PasswordReset/ForgotPassword/create-password-reset-link")
                  .param("email", "user" + i + "@webgoat.org"))
          .andExpect(status().isOk())
          .andExpect(notCompleted());
    }
    Assertions.assertThat(tokenStore.size()).isEqualTo(ResetTokenStore.MAX_REQUESTS_PER_WINDOW);
  }

  @Test
  void knownLinkShouldReturnPasswordResetPage() throws Exception {
    String token = tokenStore.issue("test");
    MvcResult mvcResult =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", token))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();

    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void interceptedTomLinkCannotBeUsedToTakeOverTomsAccount() throws Exception {
    String tomsToken = tokenStore.issue("tom");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", tomsToken)
                .param("password", "123456"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "123456"))
        .andExpect(status().isOk())
        .andExpect(notCompleted());
  }

  @Test
  void ownLinkCanBeUsedOnceByItsOwner() throws Exception {
    String link = tokenStore.issue("test");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", link)
                .param("password", "new_password"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/success.html"));
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                .param("resetLink", link)
                .param("password", "new_password"))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
  }
}
