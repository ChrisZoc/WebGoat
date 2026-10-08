/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson6bTest extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  private String passwordOf(String sql, String user) throws Exception {
    try (var connection = dataSource.getConnection();
        var statement = connection.prepareStatement(sql)) {
      statement.setString(1, user);
      try (var rs = statement.executeQuery()) {
        assertThat(rs.next()).isTrue();
        return rs.getString(1);
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"passW0rD", "dave", "John"})
  public void wellKnownPasswordsAreRefused(String password) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", password))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void davesPasswordIsRandomPerSchema() throws Exception {
    String password =
        passwordOf("select password from user_system_data where user_name = ?", "dave");
    assertThat(password).isNotEqualTo("passW0rD").startsWith("d").hasSizeGreaterThan(1);

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", password))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void tomsChallengePasswordIsRandomPerSchema() throws Exception {
    String password = passwordOf("select password from sql_challenge_users where userid = ?", "tom");
    assertThat(password).isNotEqualTo("thisisasecretfortomonly");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/login")
                .param("username_login", "tom")
                .param("password_login", "thisisasecretfortomonly"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void blindInjectionInRegistrationIsNotAnOracle() throws Exception {
    // the injected condition is bound as a plain user name: no user with that name exists, so
    // the account is created instead of answering "user already exists" for a true condition
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "tom' AND '1'='1")
                .param("email_reg", "someone@example.com")
                .param("password_reg", "password")
                .param("confirm_password", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", org.hamcrest.Matchers.containsString("created")));
  }
}
