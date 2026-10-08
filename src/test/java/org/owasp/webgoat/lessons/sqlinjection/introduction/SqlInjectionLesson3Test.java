/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson3Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @Test
  public void clientSuppliedUpdateIsNotExecuted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "update employees set department='Sales' where last_name='Barnett'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("disabled")));

    try (var connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement("select department from employees where last_name = ?")) {
      statement.setString(1, "Barnett");
      try (var rs = statement.executeQuery()) {
        assertThat(rs.next()).isTrue();
        assertThat(rs.getString(1)).isEqualTo("Development");
      }
    }
  }
}
