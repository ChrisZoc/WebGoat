/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson4Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @ParameterizedTest
  @ValueSource(
      strings = {
        "alter table employees add column phone varchar(20)",
        "alter table employees drop column phone"
      })
  public void clientSuppliedDdlIsNotExecuted(String query) throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack4").param("query", query))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("disabled")));

    try (var connection = dataSource.getConnection();
        var rs = connection.getMetaData().getColumns(null, null, "EMPLOYEES", "PHONE")) {
      assertThat(rs.next()).isFalse();
    }
  }
}
